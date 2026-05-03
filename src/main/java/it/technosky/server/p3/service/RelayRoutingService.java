package it.technosky.server.p3.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.technosky.server.p3.address.ORAddress;

@Service
public class RelayRoutingService {

    private final List<RouteEntry> routeEntries;

    public RelayRoutingService(@Value("${amhs.relay.routing-table:}") String routingTable) {
        this.routeEntries = parse(routingTable);
    }

    public Optional<RelayNextHop> findNextHop(AMHSMessageEnvelope envelope, int attempt) {
        ORAddress recipient = envelope.recipient();
        for (RouteEntry entry : routeEntries) {
            if (!entry.matches(recipient.attributes())) {
                continue;
            }
            if (entry.nextHops().isEmpty()) {
                continue;
            }
            int index = Math.floorMod(attempt, entry.nextHops().size());
            return Optional.of(new RelayNextHop(entry.nextHops().get(index), entry.criteria()));
        }
        return Optional.empty();
    }

    public boolean hasRoutesConfigured() {
        return !routeEntries.isEmpty();
    }

    private List<RouteEntry> parse(String routingTable) {
        if (!StringUtils.hasText(routingTable)) {
            return List.of();
        }

        List<RouteEntry> routes = new ArrayList<>();
        String[] rows = routingTable.split(";");
        for (String row : rows) {
            if (!StringUtils.hasText(row) || !row.contains("->")) {
                continue;
            }

            String[] parts = row.split("->", 2);
            Map<String, String> criteria = ORAddress.parse(parts[0].trim()).attributes();
            List<String> hops = List.of(parts[1].split("\\|"))
                .stream()
                .map(String::trim)
                .filter(StringUtils::hasText)
                .map(h -> h.toLowerCase(Locale.ROOT))
                .toList();
            routes.add(new RouteEntry(criteria, hops));
        }
        return List.copyOf(routes);
    }

    private record RouteEntry(Map<String, String> criteria, List<String> nextHops) {
        boolean matches(Map<String, String> recipient) {
            return criteria.entrySet().stream()
                .allMatch(e -> e.getValue().equalsIgnoreCase(recipient.getOrDefault(e.getKey(), "")));
        }
    }

    public record RelayNextHop(String endpoint, Map<String, String> matchedRoute) {
    }

    public record AMHSMessageEnvelope(ORAddress recipient, String transferTrace) {
    }
}
