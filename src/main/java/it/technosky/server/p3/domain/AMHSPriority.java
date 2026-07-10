package it.technosky.server.p3.domain;

/** AMHS priority (Normal, Non-Urgent, Urgent) 
 * is part of the P3SubmitCodec operation **/
public enum AMHSPriority {
    NORMAL(0, "normal"),
    NON_URGENT(1, "non-urgent"),
    URGENT(2, "urgent"),
    UNKNOWN(-1, "unknown");

    private final int value;
    private final String label;

    AMHSPriority(int value, String label) {
        this.value = value;
        this.label = label;
    }

    public int value() {
        return value;
    }

    public String label() {
        return label;
    }

    public static AMHSPriority fromValue(int value) {
        return switch (value) {
            case 0 -> NORMAL;
            case 1 -> NON_URGENT;
            case 2 -> URGENT;
            default -> UNKNOWN;
        };
    }
}