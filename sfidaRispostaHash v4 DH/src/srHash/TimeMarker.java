package srHash;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

public class TimeMarker implements TimeMarkerInterface {
    private int counter = 0;

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

        return MessageDigest.isEqual(expectedHash, hashReceived);
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
