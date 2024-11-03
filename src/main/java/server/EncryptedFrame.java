package server;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class EncryptedFrame implements Frame {
    Map<String,byte[]> map = new HashMap<>();

    @Override
    public void set(String key, byte[] value) {
        map.put(key, value);
    }

    @Override
    public byte[] get(String key) {
        return map.get(key);
    }

    @Override
    public void show() {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
    }

}
