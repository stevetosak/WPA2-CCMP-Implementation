package server;

public class PTKWrapper {
    public byte[] KCK = new byte[16];  // key confirmation key

    public byte[] KEK = new byte[16]; // key encryption key

    public byte[] TK = new byte[16]; // temporal key


    PTKWrapper(byte[] PTK) {
        System.arraycopy(PTK,0,KCK,0,16);
        System.arraycopy(PTK,16,KEK,0,16);
        System.arraycopy(PTK,32,TK,0,16);
    }

}
