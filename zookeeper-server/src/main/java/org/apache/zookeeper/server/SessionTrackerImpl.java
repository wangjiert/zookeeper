/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper.server;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.MessageFormat;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.KeeperException.SessionExpiredException;
import org.apache.zookeeper.common.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a full featured SessionTracker. It tracks session in grouped by tick
 * interval. It always rounds up the tick interval to provide a sort of grace
 * period. Sessions are thus expired in batches made up of sessions that expire
 * in a given interval.
 */
public class SessionTrackerImpl extends ZooKeeperCriticalThread implements
        SessionTracker {
    private static final Logger LOG = LoggerFactory.getLogger(SessionTrackerImpl.class);

    //目前看来这个里面的对象根本就不会被更新 是因为会话超时时间不会变吗
    protected final ConcurrentHashMap<Long, SessionImpl> sessionsById =
        new ConcurrentHashMap<Long, SessionImpl>();

    //为什么它有这个东西  qurompeer的超时线程里面也有这个
    private final ExpiryQueue<SessionImpl> sessionExpiryQueue;

    //引用的是zookeeper server的集合对象
    private final ConcurrentMap<Long, Integer> sessionsWithTimeout;
    //并不是从0开始的 所以每个peer都会自己负责自己的client的会话id分配
    private final AtomicLong nextSessionId = new AtomicLong();

    public static class SessionImpl implements Session {
        SessionImpl(long sessionId, int timeout) {
            this.sessionId = sessionId;
            this.timeout = timeout;
            isClosing = false;
        }

        final long sessionId;
        final int timeout;
        boolean isClosing;

        Object owner;

        public long getSessionId() { return sessionId; }
        public int getTimeout() { return timeout; }
        public boolean isClosing() { return isClosing; }

        public String toString() {
            return "0x" + Long.toHexString(sessionId);
        }
    }

    /**
     * Generates an initial sessionId. High order byte is serverId, next 5
     * 5 bytes are from timestamp, and low order 2 bytes are 0s.
     */
    public static long initializeNextSession(long id) {
        long nextSid;
        //最高的8位是服务端id
        //接下来四十位是时间
        //接下来十六位是0
        //>>>是无符号位移
        nextSid = (Time.currentElapsedTime() << 24) >>> 8;
        nextSid =  nextSid | (id <<56);
        if (nextSid == EphemeralType.CONTAINER_EPHEMERAL_OWNER) {
            ++nextSid;  // this is an unlikely edge case, but check it just in case
        }
        return nextSid;
    }

    //这个就是zookeeper server
    private final SessionExpirer expirer;

    //会话id是这个对象初始化的
    public SessionTrackerImpl(SessionExpirer expirer,
            ConcurrentMap<Long, Integer> sessionsWithTimeout, int tickTime,
            long serverId, ZooKeeperServerListener listener)
    {
        super("SessionTracker", listener);
        this.expirer = expirer;
        //哎 这个不是连接工厂创建了一个的吗
        //哇哦 原来这个东西是不会管理连接超时的
        this.sessionExpiryQueue = new ExpiryQueue<SessionImpl>(tickTime);
        this.sessionsWithTimeout = sessionsWithTimeout;
        this.nextSessionId.set(initializeNextSession(serverId));
        for (Entry<Long, Integer> e : sessionsWithTimeout.entrySet()) {
            //向sessionById集合添加对象并更新会话超时时间
            trackSession(e.getKey(), e.getValue());
        }

        EphemeralType.validateServerId(serverId);
    }

    volatile boolean running = true;

    public void dumpSessions(PrintWriter pwriter) {
        pwriter.print("Session ");
        sessionExpiryQueue.dump(pwriter);
    }

    /**
     * Returns a mapping from time to session IDs of sessions expiring at that time.
     */
    synchronized public Map<Long, Set<Long>> getSessionExpiryMap() {
        // Convert time -> sessions map to time -> session IDs map
        Map<Long, Set<SessionImpl>> expiryMap = sessionExpiryQueue.getExpiryMap();
        Map<Long, Set<Long>> sessionExpiryMap = new TreeMap<Long, Set<Long>>();
        for (Entry<Long, Set<SessionImpl>> e : expiryMap.entrySet()) {
            Set<Long> ids = new HashSet<Long>();
            sessionExpiryMap.put(e.getKey(), ids);
            for (SessionImpl s : e.getValue()) {
                ids.add(s.sessionId);
            }
        }
        return sessionExpiryMap;
    }

    @Override
    public String toString() {
        StringWriter sw = new StringWriter();
        PrintWriter pwriter = new PrintWriter(sw);
        dumpSessions(pwriter);
        pwriter.flush();
        pwriter.close();
        return sw.toString();
    }

    @Override
    //哇哦 这不就是在做超时线程的工作吗
    //好像不对呀 这里没有关闭 额也关闭了
    public void run() {
        try {
            while (running) {
                long waitTime = sessionExpiryQueue.getWaitTime();
                if (waitTime > 0) {
                    Thread.sleep(waitTime);
                    continue;
                }

                for (SessionImpl s : sessionExpiryQueue.poll()) {
                    setSessionClosing(s.sessionId);
                    expirer.expire(s);
                }
            }
        } catch (InterruptedException e) {
            handleException(this.getName(), e);
        }
        LOG.info("SessionTrackerImpl exited loop!");
    }

    synchronized public boolean touchSession(long sessionId, int timeout) {
        SessionImpl s = sessionsById.get(sessionId);

        if (s == null) {
            logTraceTouchInvalidSession(sessionId, timeout);
            return false;
        }

        if (s.isClosing()) {
            logTraceTouchClosingSession(sessionId, timeout);
            return false;
        }

        updateSessionExpiry(s, timeout);
        return true;
    }

    //更新会话的超时时间
    private void updateSessionExpiry(SessionImpl s, int timeout) {
        logTraceTouchSession(s.sessionId, timeout, "");
        sessionExpiryQueue.update(s, timeout);
    }

    private void logTraceTouchSession(long sessionId, int timeout, String sessionStatus){
        if (!LOG.isTraceEnabled())
            return;

        String msg = MessageFormat.format(
                "SessionTrackerImpl --- Touch {0}session: 0x{1} with timeout {2}",
                sessionStatus, Long.toHexString(sessionId), Integer.toString(timeout));

        ZooTrace.logTraceMessage(LOG, ZooTrace.CLIENT_PING_TRACE_MASK, msg);
    }

    private void logTraceTouchInvalidSession(long sessionId, int timeout) {
        logTraceTouchSession(sessionId, timeout, "invalid ");
    }

    private void logTraceTouchClosingSession(long sessionId, int timeout) {
        logTraceTouchSession(sessionId, timeout, "closing ");
    }

    public int getSessionTimeout(long sessionId) {
        return sessionsWithTimeout.get(sessionId);
    }

    //就是从sessionById里面删除对象
    synchronized public void setSessionClosing(long sessionId) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Session closing: 0x" + Long.toHexString(sessionId));
        }
        SessionImpl s = sessionsById.get(sessionId);
        if (s == null) {
            return;
        }
        s.isClosing = true;
    }

    synchronized public void removeSession(long sessionId) {
        LOG.debug("Removing session 0x" + Long.toHexString(sessionId));
        SessionImpl s = sessionsById.remove(sessionId);
        sessionsWithTimeout.remove(sessionId);
        if (LOG.isTraceEnabled()) {
            ZooTrace.logTraceMessage(LOG, ZooTrace.SESSION_TRACE_MASK,
                    "SessionTrackerImpl --- Removing session 0x"
                    + Long.toHexString(sessionId));
        }
        if (s != null) {
            sessionExpiryQueue.remove(s);
        }
    }

    public void shutdown() {
        LOG.info("Shutting down");

        running = false;
        if (LOG.isTraceEnabled()) {
            ZooTrace.logTraceMessage(LOG, ZooTrace.getTextTraceLevel(),
                                     "Shutdown SessionTrackerImpl!");
        }
    }

    //并没有往dbtree的集合里面加入
    public long createSession(int sessionTimeout) {
        long sessionId = nextSessionId.getAndIncrement();
        trackSession(sessionId, sessionTimeout);
        return sessionId;
    }

    @Override
    //如果sessionsById没有这个key的话就添加 并更新会话的超时时间
    public synchronized boolean trackSession(long id, int sessionTimeout) {
        boolean added = false;

        SessionImpl session = sessionsById.get(id);
        //看这里的逻辑 sessionImpl里面的超时时间应该没用呀 都没更改过
        if (session == null){
            session = new SessionImpl(id, sessionTimeout);
        }

        // findbugs2.0.3 complains about get after put.
        // long term strategy would be use computeIfAbsent after JDK 1.8
        SessionImpl existedSession = sessionsById.putIfAbsent(id, session);

        if (existedSession != null) {
            session = existedSession;
        } else {
            added = true;
            LOG.debug("Adding session 0x" + Long.toHexString(id));
        }

        if (LOG.isTraceEnabled()) {
            String actionStr = added ? "Adding" : "Existing";
            ZooTrace.logTraceMessage(LOG, ZooTrace.SESSION_TRACE_MASK,
                    "SessionTrackerImpl --- " + actionStr + " session 0x"
                    + Long.toHexString(id) + " " + sessionTimeout);
        }

        //用不更新sessionById是不是也因为这里用的时候需要这个对象地址是个定值
        updateSessionExpiry(session, sessionTimeout);
        return added;
    }

    public synchronized boolean commitSession(long id, int sessionTimeout) {
        return sessionsWithTimeout.put(id, sessionTimeout) == null;
    }

    public boolean isTrackingSession(long sessionId) {
        return sessionsById.containsKey(sessionId);
    }

    public synchronized void checkSession(long sessionId, Object owner)
            throws KeeperException.SessionExpiredException,
            KeeperException.SessionMovedException,
            KeeperException.UnknownSessionException {
        LOG.debug("Checking session 0x" + Long.toHexString(sessionId));
        SessionImpl session = sessionsById.get(sessionId);

        if (session == null) {
            throw new KeeperException.UnknownSessionException();
        }

        if (session.isClosing()) {
            throw new KeeperException.SessionExpiredException();
        }

        //创建会话的时候owner是null
        if (session.owner == null) {
            session.owner = owner;
        } else if (session.owner != owner) {
            throw new KeeperException.SessionMovedException();
        }
    }

    synchronized public void setOwner(long id, Object owner) throws SessionExpiredException {
        SessionImpl session = sessionsById.get(id);
        if (session == null || session.isClosing()) {
            throw new KeeperException.SessionExpiredException();
        }
        session.owner = owner;
    }

    public void checkGlobalSession(long sessionId, Object owner)
            throws KeeperException.SessionExpiredException,
            KeeperException.SessionMovedException {
        try {
            checkSession(sessionId, owner);
        } catch (KeeperException.UnknownSessionException e) {
            throw new KeeperException.SessionExpiredException();
        }
    }

    //说明这个对象肯定不会处理localsession
    //看不懂啊 localsession的tracker也是用的这个方法
    public long getLocalSessionCount() {
        return 0;
    }
}
