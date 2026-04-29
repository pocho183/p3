package it.technosky.server.p3.service;

import java.util.Date;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Service;

import it.technosky.server.p3.domain.AMHSMessage;
import it.technosky.server.p3.domain.AMHSMessageState;

@Service
public class AMHSMessageStateMachine {

    private static final Map<AMHSMessageState, Set<AMHSMessageState>> ALLOWED_TRANSITIONS = new EnumMap<>(AMHSMessageState.class);

    static {
        ALLOWED_TRANSITIONS.put(AMHSMessageState.SUBMITTED, EnumSet.of(AMHSMessageState.TRANSFERRED, AMHSMessageState.DEFERRED, AMHSMessageState.FAILED, AMHSMessageState.EXPIRED));
        ALLOWED_TRANSITIONS.put(AMHSMessageState.TRANSFERRED, EnumSet.of(AMHSMessageState.DELIVERED, AMHSMessageState.DEFERRED, AMHSMessageState.FAILED, AMHSMessageState.EXPIRED));
        ALLOWED_TRANSITIONS.put(AMHSMessageState.DEFERRED, EnumSet.of(AMHSMessageState.TRANSFERRED, AMHSMessageState.DELIVERED, AMHSMessageState.FAILED, AMHSMessageState.EXPIRED));
        ALLOWED_TRANSITIONS.put(AMHSMessageState.DELIVERED, EnumSet.of(AMHSMessageState.REPORTED, AMHSMessageState.FAILED));
        ALLOWED_TRANSITIONS.put(AMHSMessageState.FAILED, EnumSet.of(AMHSMessageState.REPORTED));
        ALLOWED_TRANSITIONS.put(AMHSMessageState.EXPIRED, EnumSet.of(AMHSMessageState.REPORTED));
        ALLOWED_TRANSITIONS.put(AMHSMessageState.REPORTED, EnumSet.noneOf(AMHSMessageState.class));
    }

    public void initialize(AMHSMessage message) {
        transition(message, AMHSMessageState.SUBMITTED);
    }

    public void transition(AMHSMessage message, AMHSMessageState targetState) {
        AMHSMessageState currentState = message.getLifecycleState();
        if (currentState == null) {
            message.setLifecycleState(targetState);
            message.setLastStateChange(new Date());
            return;
        }

        if (currentState == targetState) {
            return;
        }

        Set<AMHSMessageState> allowed = ALLOWED_TRANSITIONS.getOrDefault(currentState, EnumSet.noneOf(AMHSMessageState.class));
        if (!allowed.contains(targetState)) {
            throw new IllegalStateException("Invalid message state transition from " + currentState + " to " + targetState);
        }

        message.setLifecycleState(targetState);
        message.setLastStateChange(new Date());
    }
}
