import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class BypassVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        return true; // Всегда доверяем — уязвимость!
    }
}
