package it.technosky.server.p3.repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import it.technosky.server.p3.domain.AMHSMessage;
import it.technosky.server.p3.domain.AMHSMessageState;
import it.technosky.server.p3.domain.AMHSProfile;

@Repository
public interface AMHSMessageRepository extends JpaRepository<AMHSMessage, Long> {

	Optional<AMHSMessage> findByMessageId(String messageId);

	Optional<AMHSMessage> findByMtsIdentifier(String mtsIdentifier);

	List<AMHSMessage> findByChannelNameIgnoreCase(String channelName);

	List<AMHSMessage> findByProfile(AMHSProfile profile);

	List<AMHSMessage> findByChannelNameIgnoreCaseAndProfile(String channelName, AMHSProfile profile);

	List<AMHSMessage> findByLifecycleStateIn(List<AMHSMessageState> states);

	long deleteByReceivedAtBefore(Date cutoff);

}
