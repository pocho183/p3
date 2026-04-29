package it.technosky.server.p3.channel;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.api.ChannelRequest;
import it.technosky.server.p3.domain.AMHSChannel;
import it.technosky.server.p3.repository.AMHSChannelRepository;

@Service
public class AMHSChannelService {

    public static final String DEFAULT_CHANNEL_NAME = "ATFM";

    private final AMHSChannelRepository channelRepository;
    private final boolean databaseEnabled;

    public AMHSChannelService(
        AMHSChannelRepository channelRepository,
        @Value("${amhs.database.enabled:true}") boolean databaseEnabled
    ) {
        this.channelRepository = channelRepository;
        this.databaseEnabled = databaseEnabled;
    }

    @Transactional
    public AMHSChannel createOrUpdate(ChannelRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Channel request cannot be null");
        }
        if (!StringUtils.hasText(request.name())) {
            throw new IllegalArgumentException("Channel name is required");
        }

        String normalizedName = normalizeChannelName(request.name());

        AMHSChannel channel = channelRepository.findByNameIgnoreCase(normalizedName)
            .orElseGet(AMHSChannel::new);

        channel.setName(normalizedName);
        channel.setExpectedCn(normalize(request.expectedCn()));
        channel.setExpectedOu(normalize(request.expectedOu()));
        channel.setEnabled(request.enabled() == null || request.enabled());

        return channelRepository.save(channel);
    }

    @Transactional(readOnly = true)
    public List<AMHSChannel> findAll() {
        return channelRepository.findAll();
    }

    @Transactional
    public AMHSChannel requireEnabledChannel(String channelName) {
        String normalized = normalizeChannelName(channelName);

        AMHSChannel channel = channelRepository.findByNameIgnoreCase(normalized)
            .orElseGet(() -> resolveMissingChannel(normalized));

        if (!channel.isEnabled()) {
            throw new IllegalArgumentException("AMHS channel is disabled: " + normalized);
        }

        return channel;
    }

    private AMHSChannel resolveMissingChannel(String normalizedChannelName) {
        if (!databaseEnabled) {
            if (DEFAULT_CHANNEL_NAME.equals(normalizedChannelName)) {
                return buildEnabledChannel(DEFAULT_CHANNEL_NAME);
            }
            throw new IllegalArgumentException("Unknown AMHS channel: " + normalizedChannelName);
        }

        if (DEFAULT_CHANNEL_NAME.equals(normalizedChannelName)) {
            AMHSChannel channel = buildEnabledChannel(DEFAULT_CHANNEL_NAME);
            return channelRepository.save(channel);
        }

        throw new IllegalArgumentException("Unknown AMHS channel: " + normalizedChannelName);
    }

    private String normalizeChannelName(String channelName) {
        return StringUtils.hasText(channelName)
            ? channelName.trim().toUpperCase()
            : DEFAULT_CHANNEL_NAME;
    }

    private AMHSChannel buildEnabledChannel(String channelName) {
        AMHSChannel channel = new AMHSChannel();
        channel.setName(channelName);
        channel.setExpectedCn(null);
        channel.setExpectedOu(null);
        channel.setEnabled(true);
        return channel;
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}