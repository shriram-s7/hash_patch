package com.example.dispatch;

/**
 * RuntimeDynamicDispatch.java — the boundary Strategy 6 (interface-based
 * dispatch) must NOT cross: `impl`'s concrete type is chosen at RUNTIME
 * from an environment variable via Class.forName, not statically knowable
 * from the project's own source — genuinely different from
 * InterfaceDispatchExample.java's `provider` parameter, whose static type
 * (the AlgorithmProvider interface) and set of implementers are both fully
 * visible in this same project. Mirrors test2's real
 * RuntimeProvider.java::sign() case. Must stay UNRESOLVED, never guessed.
 */
public class RuntimeDynamicDispatch {

    interface SigningProvider {
        byte[] sign(byte[] payload) throws Exception;
    }

    public static byte[] sign(byte[] payload) throws Exception {
        String impl = System.getenv("SIGNING_PROVIDER_CLASS");
        Class<?> type = Class.forName(impl);
        Object instance = type.getDeclaredConstructor().newInstance();
        return ((SigningProvider) instance).sign(payload);
    }
}
