import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.*;

class FirewallTest {
    Firewall firewall;
    @BeforeEach
    void setUp() throws IOException {
        firewall = new Firewall("rules.csv");
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void accept_packet() {
        assertEquals(true, firewall.accept_packet("inbound", "udp","1","0.0.0.0"));
        assertEquals(false, firewall.accept_packet("inbound", "tcp","1","0.0.0.0"));
        assertEquals(true, firewall.accept_packet("outbound", "udp", "83", "192.168.24.1"));
        assertEquals(false, firewall.accept_packet("outbound", "tcp", "3", "33.33.33.33"));
        assertEquals(true, firewall.accept_packet("outbound", "udp", "65535", "0.0.0.3"));
        assertEquals(true, firewall.accept_packet("inbound", "tcp", "15000", "192.168.1.1"));
    }

}