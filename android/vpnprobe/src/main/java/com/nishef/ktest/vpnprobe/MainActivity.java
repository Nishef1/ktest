package com.nishef.ktest.vpnprobe;

import android.app.Activity;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.RouteInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;

/**
 * Device-only acceptance probe. This app has a separate Android UID from KTest,
 * so its traffic is captured by KTest's VpnService instead of being excluded
 * with the KTest app's own upstream sockets.
 */
public final class MainActivity extends Activity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private TextView output;
    private Button runButton;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(20);
        page.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("KTest VPN Probe");
        title.setTextSize(24);
        page.addView(title, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView description = new TextView(this);
        description.setText("Install this separate test app, connect KTest System VPN, then run these checks. Its traffic is not excluded from the VPN. Results stay on this device.");
        description.setTextSize(14);
        LinearLayout.LayoutParams descriptionParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        descriptionParams.topMargin = dp(10);
        page.addView(description, descriptionParams);

        runButton = new Button(this);
        runButton.setText("Run traffic checks");
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        buttonParams.topMargin = dp(16);
        page.addView(runButton, buttonParams);

        output = new TextView(this);
        output.setTextSize(14);
        output.setTextIsSelectable(true);
        output.setText("Not run yet. Connect KTest System VPN before starting.");
        ScrollView scroll = new ScrollView(this);
        LinearLayout.LayoutParams outputParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1);
        outputParams.topMargin = dp(16);
        scroll.addView(output);
        page.addView(scroll, outputParams);

        setContentView(page);
        runButton.setOnClickListener(v -> runChecks());
    }

    private void runChecks() {
        runButton.setEnabled(false);
        output.setText("Testing DNS, HTTPS, IPv6 (when routed), and arbitrary UDP...");
        worker.execute(() -> {
            StringBuilder report = new StringBuilder();
            report.append("KTest VPN traffic acceptance\n");
            report.append("This app uses a separate UID from KTest.\n\n");

            try {
                InetAddress[] addresses = InetAddress.getAllByName("www.cloudflare.com");
                report.append("System DNS: PASS (www.cloudflare.com -> ")
                    .append(addresses.length).append(" address(es))\n");
            } catch (Exception e) {
                report.append("System DNS: FAIL (").append(category(e)).append(")\n");
            }
            report.append("DNS over UDP / TUN: ").append(dnsUdp()).append("\n");

            ProbeResult cloudflare = https("https://www.cloudflare.com/cdn-cgi/trace");
            report.append("HTTPS / Cloudflare trace: ").append(cloudflare.summary).append("\n");
            if (cloudflare.body != null) {
                for (String line : cloudflare.body.split("\\r?\\n")) {
                    if (line.startsWith("ip=") || line.startsWith("loc=")) {
                        report.append("  ").append(line).append("\n");
                    }
                }
            }

            ProbeResult google = https("https://www.google.com/generate_204");
            report.append("HTTPS / Google 204: ").append(google.summary).append("\n");

            if (hasIpv6DefaultRoute()) {
                ProbeResult ipv6 = https("https://ipv6.icanhazip.com/");
                report.append("IPv6 HTTPS: ").append(ipv6.summary).append("\n");
                if (ipv6.body != null && !ipv6.body.trim().isEmpty()) {
                    report.append("  IPv6 egress: ").append(ipv6.body.trim()).append("\n");
                }
            } else {
                report.append("IPv6 HTTPS: SKIP (the active VPN has no IPv6 default route)\n");
            }

            report.append("UDP / STUN: ").append(stun()).append("\n");
            report.append("\nInterpretation: a PASS proves this app completed that request through its active Android network path. A failure can also be destination- or ISP-specific; repeat against another network before attributing it to the packet adapter. DNS/HTTPS success does not prove every UDP application works.");
            String finalReport = report.toString();
            main.post(() -> {
                output.setText(finalReport);
                runButton.setEnabled(true);
            });
        });
    }

    private ProbeResult https(String rawUrl) {
        HttpsURLConnection connection = null;
        try {
            connection = (HttpsURLConnection) new URL(rawUrl).openConnection();
            connection.setConnectTimeout(7000);
            connection.setReadTimeout(7000);
            connection.setInstanceFollowRedirects(false);
            int status = connection.getResponseCode();
            InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            String body = stream == null ? "" : readBounded(stream, 8192);
            boolean ok = status >= 200 && status < 400;
            return new ProbeResult((ok ? "PASS" : "FAIL") + " (HTTP " + status + ")",
                body, ok);
        } catch (Exception e) {
            return new ProbeResult("FAIL (" + category(e) + ")", null, false);
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private String dnsUdp() {
        DatagramSocket socket = null;
        try {
            byte[] query = new byte[12 + 17];
            byte[] id = new byte[2];
            new SecureRandom().nextBytes(id);
            query[0] = id[0];
            query[1] = id[1];
            query[2] = 1; // Recursion desired
            query[5] = 1; // One question
            int p = 12;
            query[p++] = 7;
            byte[] example = "example".getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(example, 0, query, p, example.length);
            p += example.length;
            query[p++] = 3;
            byte[] com = "com".getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(com, 0, query, p, com.length);
            p += com.length;
            query[p++] = 0;
            query[p++] = 0;
            query[p++] = 1; // A
            query[p++] = 0;
            query[p] = 1; // IN

            socket = new DatagramSocket();
            socket.connect(InetAddress.getByName("1.1.1.1"), 53);
            socket.setSoTimeout(3000);
            socket.send(new DatagramPacket(query, query.length));
            byte[] bytes = new byte[2048];
            DatagramPacket response = new DatagramPacket(bytes, bytes.length);
            socket.receive(response);
            if (response.getLength() < 12 || bytes[0] != id[0] || bytes[1] != id[1]) {
                return "FAIL (invalid DNS response)";
            }
            if ((bytes[2] & 0x80) == 0 || (bytes[3] & 0x0f) != 0) {
                return "FAIL (DNS error response)";
            }
            int answers = ((bytes[6] & 0xff) << 8) | (bytes[7] & 0xff);
            return answers > 0 ? "PASS (DNS response received through UDP)" : "FAIL (empty DNS answer)";
        } catch (Exception e) {
            return "FAIL (" + category(e) + ")";
        } finally {
            if (socket != null) socket.close();
        }
    }

    private String stun() {
        DatagramSocket socket = null;
        try {
            InetAddress server = InetAddress.getByName("stun.l.google.com");
            byte[] request = new byte[20];
            request[0] = 0;
            request[1] = 1; // Binding Request
            request[4] = 0x21;
            request[5] = 0x12;
            request[6] = (byte) 0xA4;
            request[7] = 0x42;
            byte[] transaction = new byte[12];
            new SecureRandom().nextBytes(transaction);
            System.arraycopy(transaction, 0, request, 8, transaction.length);

            socket = new DatagramSocket();
            socket.connect(server, 19302);
            socket.setSoTimeout(3000);
            socket.send(new DatagramPacket(request, request.length));
            byte[] bytes = new byte[2048];
            DatagramPacket response = new DatagramPacket(bytes, bytes.length);
            socket.receive(response);
            if (response.getLength() < 20 || bytes[0] != 1 || bytes[1] != 1 ||
                bytes[4] != 0x21 || bytes[5] != 0x12 ||
                bytes[6] != (byte) 0xA4 || bytes[7] != 0x42) {
                return "FAIL (invalid STUN response)";
            }
            for (int i = 0; i < transaction.length; i++) {
                if (bytes[8 + i] != transaction[i]) return "FAIL (transaction mismatch)";
            }
            return "PASS (STUN Binding Response received)";
        } catch (Exception e) {
            return "FAIL (" + category(e) + ")";
        } finally {
            if (socket != null) socket.close();
        }
    }

    private boolean hasIpv6DefaultRoute() {
        try {
            ConnectivityManager manager = (ConnectivityManager)
                getSystemService(Context.CONNECTIVITY_SERVICE);
            Network active = manager.getActiveNetwork();
            LinkProperties properties = active == null ? null : manager.getLinkProperties(active);
            if (properties == null) return false;
            for (RouteInfo route : properties.getRoutes()) {
                if (route.getDestination().getPrefixLength() == 0 &&
                    route.getDestination().getAddress() instanceof Inet6Address) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            // A missing route is reported as SKIP, not as a failed IPv6 request.
        }
        return false;
    }

    private static String readBounded(InputStream stream, int maxBytes) throws Exception {
        try (InputStream input = stream; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int total = 0;
            int read;
            while (total < maxBytes && (read = input.read(buffer, 0, Math.min(buffer.length, maxBytes - total))) >= 0) {
                output.write(buffer, 0, read);
                total += read;
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static String category(Exception e) {
        String name = e.getClass().getSimpleName();
        if (name.contains("UnknownHost")) return "DNS resolution failed";
        if (name.contains("SocketTimeout")) return "timeout";
        if (name.contains("SSL") || name.contains("Certificate")) return "TLS verification failed";
        if (name.contains("ConnectException")) return "connection refused";
        if (name.contains("SocketException")) return "socket/network failure";
        return name.isEmpty() ? "network request failed" : name;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }

    private static final class ProbeResult {
        final String summary;
        final String body;
        final boolean ok;

        ProbeResult(String summary, String body, boolean ok) {
            this.summary = summary;
            this.body = body;
            this.ok = ok;
        }
    }
}
