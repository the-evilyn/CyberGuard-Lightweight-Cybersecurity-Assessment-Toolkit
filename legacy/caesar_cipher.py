def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def decrypt(text, shift):
    return encrypt(text, -shift)

def brute_force(text):
    print("\n🔓 Brute Force Attack - All possible decryptions:")
    print("=" * 50)
    for shift in range(1, 26):
        print(f"Shift {shift:2d}: {encrypt(text, -shift)}")

def main():
    print("🔤 Caesar Cipher Tool")
    print("=" * 40)
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Brute Force")
    choice = input("\nSelect option (1/2/3): ")

    if choice in ['1', '2']:
        text = input("Enter text: ")
        shift = int(input("Enter shift (1-25): "))
        if choice == '1':
            print(f"\n✅ Encrypted: {encrypt(text, shift)}")
        else:
            print(f"\n✅ Decrypted: {decrypt(text, shift)}")
    elif choice == '3':
        text = input("Enter encrypted text: ")
        brute_force(text)
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
