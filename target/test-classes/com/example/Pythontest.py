from Crypto.PublicKey import ECC
from Crypto.Util import number
import timeit

def measure_pairing_time():
    # 生成橢圓曲線上的點
    curve = ECC.generate(curve='P-256')
    point_G = curve.pointQ

    # 生成兩個私鑰
    private_key_a = number.getRandomRange(1, curve.order)
    private_key_b = number.getRandomRange(1, curve.)

    # 計算相應的公鑰
    public_key_a = private_key_a * point_G
    public_key_b = private_key_b * point_G

    # 計算雙線性對
    pairing_time = timeit.timeit(lambda: point_G.pair_mul(public_key_a, private_key_b), number=1000)

    # 計算 pow 時間
    pow_time = timeit.timeit(lambda: private_key_a * point_G, number=1000)

    # 輸出結果
    print(f"Average time for pairing: {pairing_time / 1000} seconds")
    print(f"Average time for pow: {pow_time / 1000} seconds")

if __name__ == "__main__":
    measure_pairing_time()
