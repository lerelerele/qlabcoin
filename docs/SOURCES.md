# Sources

## Q6100 Hardware Reference

- Hannah J. Manetsch et al., "A tweezer array with 6100 highly coherent atomic qubits", arXiv:2403.12021v4.
  - https://arxiv.org/abs/2403.12021v4

Attack Qubits treats this as a physical-qubit and architecture inspiration, not as 6100 logical qubits.

## Shor / ECDLP Resource Estimate

- Martin Roetteler, Michael Naehrig, Krysta M. Svore, Kristin Lauter, "Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms", arXiv:1706.06752.
  - https://arxiv.org/abs/1706.06752

Reference model used in Attack Qubits:

```text
logical_qubits(n) = 9n + 2 ceil(log2 n) + 10
toffoli(n) = 448 n^3 log2(n) + 4090 n^3
```

## Post-Quantum Standards

- NIST finalized FIPS 203, 204, and 205 for ML-KEM, ML-DSA, and SLH-DSA.
  - https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards

Attack Qubits should use ML-DSA and SLH-DSA as mitigation study targets, not as early challenge primitives.
