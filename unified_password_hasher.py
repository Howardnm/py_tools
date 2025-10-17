import base64
import hmac
import os

import bcrypt
import scrypt
from argon2 import PasswordHasher


# 安装依赖:
# pip install bcrypt scrypt argon2-cffi

class PasswordHasherUnified:
    def __init__(self, method="argon2", **kwargs):
        """
        method: 'argon2' | 'bcrypt' | 'scrypt'（默认 argon2）
        kwargs: 各算法的可调参数
        """
        self.method = method.lower()
        self.kwargs = kwargs
        self._init_hasher()

    def _init_hasher(self):
        """根据当前 method 初始化 hasher"""
        if self.method == "argon2":
            self.hasher = PasswordHasher(
                time_cost=self.kwargs.get("time_cost", 3),                     # 时间成本（迭代次数）
                memory_cost=self.kwargs.get("memory_cost", 64 * 1024),         # 内存成本 (KB)
                parallelism=self.kwargs.get("parallelism", 4),                 # 并行度
                hash_len=self.kwargs.get("hash_len", 32),                      # 哈希长度 (字节)
                salt_len=self.kwargs.get("salt_len", 16),                      # 盐长度 (字节)
            )
        elif self.method == "bcrypt":
            self.rounds = self.kwargs.get("rounds", 12)                        # CPU成本，默认12轮
        elif self.method == "scrypt":
            self.N = self.kwargs.get("N", 2**15)                               # CPU/内存成本参数
            self.r = self.kwargs.get("r", 8)                                   # 块大小参数
            self.p = self.kwargs.get("p", 1)                                   # 并行度参数
            self.salt_size = self.kwargs.get("salt_size", 16)                  # 盐长度 (字节)
        else:
            raise ValueError("Unsupported method. Use 'argon2', 'bcrypt', or 'scrypt'.")

    def hash(self, password: str) -> str:
        """生成哈希字符串（自动生成随机盐）"""
        if self.method == "argon2":
            return self.hasher.hash(password)
        elif self.method == "bcrypt":
            if len(password.encode('utf-8')) > 72:  # 如果密码大于72字节，bcrypt只使用前72字节
                raise ValueError("bcrypt only supports passwords up to 72 bytes.")
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=self.rounds))
            return hashed.decode('utf-8')
        elif self.method == "scrypt":
            password_bytes = password.encode('utf-8')
            salt = os.urandom(self.salt_size)
            # 生成哈希
            hash_bytes = scrypt.hash(password_bytes, salt, N=self.N, r=self.r, p=self.p)
            salt_b64 = base64.urlsafe_b64encode(salt).decode('ascii')
            hash_b64 = base64.urlsafe_b64encode(hash_bytes).decode('ascii')
            # 存储格式：$scrypt$N=16384,r=8,p=1$盐$哈希
            return f"$scrypt$N={self.N},r={self.r},p={self.p}${salt_b64}${hash_b64}"
        else:
            raise ValueError("Unsupported method.")

    def verify(self, hash_str: str, password: str) -> bool:
        """验证密码是否正确（自动识别算法）"""
        try:
            algo = self._detect_algorithm(hash_str)
            if algo == "argon2":
                return self.hasher.verify(hash_str, password)
            elif algo == "bcrypt":
                return bcrypt.checkpw(password.encode('utf-8'), hash_str.encode('utf-8'))
            elif algo == "scrypt":
                # 解析哈希字符串: $scrypt$N=16384,r=8,p=1$盐$哈希
                parts = hash_str.split('$')
                # 解析参数
                params_str = parts[2]
                params = {}
                for param in params_str.split(','):
                    key, value = param.split('=')
                    params[key] = int(value)

                N = params['N']
                r = params['r']
                p = params['p']
                # 解码盐和哈希
                salt = base64.urlsafe_b64decode(parts[3])
                stored_hash = base64.urlsafe_b64decode(parts[4])
                # 计算新哈希
                password_bytes = password.encode('utf-8')
                new_hash = scrypt.hash(password_bytes, salt, N=N, r=r, p=p)
                # 使用 hmac.compare_digest 进行恒定时间比较
                return hmac.compare_digest(stored_hash, new_hash)
            else:
                raise ValueError("Unsupported hash format.")
        except Exception:
            return False


    @staticmethod
    def _detect_algorithm(hash_str: str) -> str:
        """根据哈希前缀识别算法类型"""
        if hash_str.startswith("$argon2"):
            return "argon2"
        elif hash_str.startswith(("$2", "$bcrypt")):
            return "bcrypt"
        elif hash_str.startswith(("$7$", "$scrypt")):
            return "scrypt"
        else:
            return "unknown"


# 验证代码
if __name__ == "__main__":
    # ✅ 1. Argon2
    ph_a = PasswordHasherUnified(method="argon2")
    hash1 = ph_a.hash("Password123!")
    print("Argon2:", hash1)
    print("Verify:", ph_a.verify(hash1, "Password123!"))

    # ✅ 2. bcrypt
    ph_b = PasswordHasherUnified(method="bcrypt")
    hash2 = ph_b.hash("Password123!")
    print("bcrypt:", hash2)
    print("Verify:", ph_b.verify(hash2, "Password123!"))

    # ✅ 3. scrypt
    ph_s = PasswordHasherUnified(method="scrypt")
    hash3 = ph_s.hash("Password123!")
    print("scrypt:", hash3)
    print("Verify:", ph_s.verify(hash3, "Password123!"))

    # ✅ 4. 验证未指定算法
    ph = PasswordHasherUnified()
    print("Verify auto-detect Argon2:", ph.verify(hash1, "Password123!"))
    print("Verify auto-detect bcrypt:", ph.verify(hash2, "Password123!"))
    print("Verify auto-detect scrypt:", ph.verify(hash3, "Password123!"))
    # ❌ 5. 错误密码验证
    print("Verify wrong password Argon2:", ph.verify(hash1, "WrongPassword"))
    # ❌ 6. 无效哈希格式
    print("Verify invalid hash:", ph.verify("invalid_hash_string", "Password123!"))

    # ✅ 7. 测试加密速度
    import time
    start = time.time()
    for _ in range(100):
        ph_a.hash("SpeedTestPassword!")
    end = time.time()
    print("Argon2 100 hashes and verifications took:", end - start, "seconds")
    start = time.time()
    for _ in range(100):
        ph_b.hash("SpeedTestPassword!")
    end = time.time()
    print("bcrypt 100 hashes and verifications took:", end - start, "seconds")
    start = time.time()
    for _ in range(100):
        ph_s.hash("SpeedTestPassword!")
    end = time.time()
    print("scrypt 100 hashes and verifications took:", end - start, "seconds")

    # ✅ 8. 长密码测试
    long_password = "A" * 1000  # 1000字符长密码
    hash_long = ph_a.hash(long_password)
    print("Long password Argon2 hash:", hash_long)
    print("Verify long password Argon2:", ph_a.verify(hash_long, long_password))
    try:
        hash_long_bcrypt = ph_b.hash(long_password)
        print("Long password bcrypt hash:", hash_long_bcrypt)
        print("Verify long password bcrypt:", ph_b.verify(hash_long_bcrypt, long_password))
    except ValueError as e:
        print("bcrypt long password error:", e)
    hash_long_scrypt = ph_s.hash(long_password)
    print("Long password scrypt hash:", hash_long_scrypt)
    print("Verify long password scrypt:", ph_s.verify(hash_long_scrypt, long_password))

    # ✅ 9. 特殊字符、非ASCII字符密码测试
    special_password = "P@$$w0rd!#%&*()_+-=[]{}|;:',.<>?/~`😊🔒"
    hash_special = ph_a.hash(special_password)
    print("Special char password Argon2 hash:", hash_special)
    print("Verify special char password Argon2:", ph_a.verify(hash_special, special_password))
    hash_special_bcrypt = ph_b.hash(special_password)
    print("Special char password bcrypt hash:", hash_special_bcrypt)
    print("Verify special char password bcrypt:", ph_b.verify(hash_special_bcrypt, special_password))
    hash_special_scrypt = ph_s.hash(special_password)
    print("Special char password scrypt hash:", hash_special_scrypt)
    print("Verify special char password scrypt:", ph_s.verify(hash_special_scrypt, special_password))









