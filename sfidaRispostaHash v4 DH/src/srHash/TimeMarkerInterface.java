package srHash;

public interface TimeMarkerInterface {
    byte[] generateMark(byte[] message, String id) throws Exception; // crea la marca
    boolean verifyMark(byte[] message, String id, byte[] mark) throws Exception; // verifica autenticità marca
}
