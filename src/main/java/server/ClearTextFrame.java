package server;

import java.util.HashMap;
import java.util.Map;

public class ClearTextFrame implements Frame {
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
    }


}
