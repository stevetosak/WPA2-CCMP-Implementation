package server;

public interface Frame{
    void set(String key, byte[] value);
    byte[] get(String key);
    void show();
}
