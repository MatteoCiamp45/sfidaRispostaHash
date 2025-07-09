package srHash;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.*;

public class TimeMarker implements TimeMarkerInterface {
    private static int counter = 0;
    private static final long TIME_WINDOW_MS = 5 * 60 * 1000; // 5 minuti
    private final Map<String, Set<String>> receivedMarks = new HashMap<>();

    // Genera la marca temporale
    public byte[] generateMark(byte[] message, String id) throws Exception {
        long timestamp = System.currentTimeMillis();

        byte[] idBytes = id.getBytes();
        byte[] tsBytes = ByteBuffer.allocate(Long.BYTES).putLong(timestamp).array();
        byte[] countBytes = ByteBuffer.allocate(Integer.BYTES).putInt(counter++).array();

        // Concatenazione: message || id || timestamp || counter
        byte[] input = concat(message, idBytes, tsBytes, countBytes);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input);

        return concat(tsBytes, countBytes, digest); // marca = timestamp || counter || hash
    }

    // Verifica la marca ricevuta
    public boolean verifyMark(byte[] message, String id, byte[] mark) throws Exception {
        if (mark.length != Long.BYTES + Integer.BYTES + 32) return false;

        ByteBuffer buffer = ByteBuffer.wrap(mark);
        long timestamp = buffer.getLong();          // estrae timestamp da marca
        int count = buffer.getInt();                // estrae counter da marca
        byte[] hashReceived = new byte[32];
        buffer.get(hashReceived);                   // estrae hash da marca

        byte[] idBytes = id.getBytes();
        byte[] tsBytes = ByteBuffer.allocate(Long.BYTES).putLong(timestamp).array();
        byte[] countBytes = ByteBuffer.allocate(Integer.BYTES).putInt(count).array();

        byte[] input = concat(message, idBytes, tsBytes, countBytes);
        byte[] expectedHash = MessageDigest.getInstance("SHA-256").digest(input);

        // 1. Verifica hash
        if (!MessageDigest.isEqual(expectedHash, hashReceived)) {
            return false;
        }

        // 2. Verifica che il timestamp sia entro la finestra accettabile (+-5 minuti)
        long now = System.currentTimeMillis();
        if (Math.abs(now - timestamp) > TIME_WINDOW_MS) {
            System.out.println("Marca scaduta o futura.");
            return false;
        }

        // 3. Prevenzione replay: verifica se la marca è già stata vista
        String key = timestamp + ":" + count;
        synchronized (receivedMarks) {
            receivedMarks.putIfAbsent(id, new HashSet<>());
            Set<String> seen = receivedMarks.get(id);
            if (seen.contains(key)) {
                System.out.println("Marca già ricevuta (replay rilevato).");
                return false;
            } else {
                seen.add(key);
            }
        }

        return true;
    }

    private byte[] concat(byte[] tsBytes, byte[] countBytes, byte[] digest) {
        int totalLength = tsBytes.length + countBytes.length + digest.length;
        byte[] result = new byte[totalLength];

        int pos = 0;
        System.arraycopy(tsBytes, 0, result, pos, tsBytes.length);
        pos += tsBytes.length;

        System.arraycopy(countBytes, 0, result, pos, countBytes.length);
        pos += countBytes.length;

        System.arraycopy(digest, 0, result, pos, digest.length);

        return result;
    }

    private byte[] concat(byte[] message, byte[] idBytes, byte[] tsBytes, byte[] countBytes) {
        int totalLength = message.length + idBytes.length + tsBytes.length + countBytes.length;
        byte[] result = new byte[totalLength];

        int pos = 0;
        System.arraycopy(message, 0, result, pos, message.length);
        pos += message.length;

        System.arraycopy(idBytes, 0, result, pos, idBytes.length);
        pos += idBytes.length;

        System.arraycopy(tsBytes, 0, result, pos, tsBytes.length);
        pos += tsBytes.length;

        System.arraycopy(countBytes, 0, result, pos, countBytes.length);

        return result;
    }
}
