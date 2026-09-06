package com.example.dispatch;

/**
 * AlgorithmProvider.java — Track A hardening corpus fixture: the interface
 * for Strategy 6 (interface-based dispatch,
 * hash_patch/detect/java_resolver.py::resolve_interface_dispatch). See
 * InterfaceDispatchExample.java for the call site and
 * ProdAlgorithmProvider.java / LegacyAlgorithmProvider.java for the two
 * concrete implementations this must resolve BOTH of.
 */
public interface AlgorithmProvider {
    String algorithmFor(String kind);
}
