import re

def check_password_strength(password):
    score = 0
    tips = []

    if len(password) >= 8:
        score += 1
    else:
        tips.append("❌ Use at least 8 characters.")

    if len(password) >= 12:
        score += 1
    else:
        tips.append("💡 Use 12+ characters for stronger security.")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        tips.append("❌ Add at least one uppercase letter (A-Z).")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        tips.append("❌ Add at least one lowercase letter (a-z).")

    if re.search(r'[0-9]', password):
        score += 1
    else:
        tips.append("❌ Add at least one number (0-9).")

    if re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        score += 1
    else:
        tips.append("❌ Add at least one special character (!@#$%^&*).")

    print("\n🔐 Password Strength Checker")
    print("=" * 40)
    print(f"Password : {'*' * len(password)}")
    print(f"Score    : {score}/6")

    if score <= 2:
        print("Strength : 🔴 Weak")
    elif score <= 4:
        print("Strength : 🟡 Moderate")
    else:
        print("Strength : 🟢 Strong")

    if tips:
        print("\n📋 Tips to improve:")
        for tip in tips:
            print(f"  {tip}")
    else:
        print("\n✅ Great password! Keep it safe.")

if __name__ == "__main__":
    pwd = input("Enter a password to check: ")
    check_password_strength(pwd)
