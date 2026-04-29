package it.technosky.server.p3.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import it.technosky.server.p3.domain.AMHSDeliveryReport;
import it.technosky.server.p3.domain.AMHSMessage;

@Repository
public interface AMHSDeliveryReportRepository extends JpaRepository<AMHSDeliveryReport, Long> {

    List<AMHSDeliveryReport> findByMessage(AMHSMessage message);

    List<AMHSDeliveryReport> findByRecipientIgnoreCaseAndIdGreaterThanOrderByIdAsc(String recipient, Long id);
}
