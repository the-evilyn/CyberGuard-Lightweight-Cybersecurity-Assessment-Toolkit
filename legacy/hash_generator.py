import hashlib

def generate_hash(text, algorithm):
    h = hashlib.new(algorithm)
    h.update(text.encode('utf-8'))
    return h.hexdigest()

def verify_hash(text, algorithm, known_hash):
    return generate_hash(text, algorithm) == known_hash

def main():
    print("#️⃣  Hash Generator & Verifier")
    print("=" * 40)
    print("1. Generate Hash")
    print("2. Verify Hash")
    choice = input("\nSelect option (1/2): ")

    algorithms = ['md5', 'sha1', 'sha256', 'sha512']

    if choice == '1':
        text = input("Enter text to hash: ")
        print("\n📋 Generated Hashes:")
        print("-" * 60)
        for algo in algorithms:
            print(f"  {algo.upper():<8}: {generate_hash(text, algo)}")
        print("-" * 60)

    elif choice == '2':
        text = input("Enter original text: ")
        print("Available algorithms: md5, sha1, sha256, sha512")
        algo = input("Enter algorithm: ").lower()
        if algo not in algorithms:
            print("❌ Invalid algorithm.")
            return
        known = input("Enter known hash to verify: ")
        if verify_hash(text, algo, known):
            print("\n✅ Hash MATCHES — data is intact!")
        else:
            print("\n❌ Hash does NOT match — data may be tampered!")
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
