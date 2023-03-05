import math
import gmpy2
import binascii
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y
#共模攻击
def common_modulus_attack(ns,es,cs):
    # 寻找公共模数
    index1 = 0
    index2 = 0
    for i in range(21):
        for j in range(i+1, 21):
            if ns[i] == ns[j]:
                #print('Same modulus found! ({}, {})'.format(i, j))
                index1, index2 = i, j
    e1 = int(es[index1], 16)
    e2 = int(es[index2], 16)
    n = int(ns[index1], 16)
    c1 = int(cs[index1], 16)
    c2 = int(cs[index2], 16)

    g, s1, s2 = extended_gcd(e1, e2)

    # 求模反元素
    if isinstance(s1, int) and s1 < 0:
        s1 = -s1
        c1 = gmpy2.invert(c1, n)
    elif isinstance(s2, int) and s2 < 0:
        s2 = -s2
        c2 = gmpy2.invert(c2, n)

    m = pow(c1, s1, n) * pow(c2, s2, n) % n

    #print('Recovered message: {}'.format(hex(m)))
    result = binascii.a2b_hex(hex(m)[2:])
    return result
#因数碰撞法
def factor_collision_attack(ns,es,cs):
    p, index1, index2 = None, None, None
    for i in range(21):
        for j in range(i+1, 21):
            if int(ns[i], 16) == int(ns[j], 16):
                continue
            gcd = gmpy2.gcd(int(ns[i], 16), int(ns[j], 16))
            if gcd != 1:
                p, index1, index2 = gcd, i, j
                break
        if p:
            break

    q1 = int(ns[index1], 16) // p
    q2 = int(ns[index2], 16) // p

    phi1 = (p-1)*(q1-1)
    phi2 = (p-1)*(q2-1)

    d1 = gmpy2.invert(int(es[index1], 16), phi1)
    d2 = gmpy2.invert(int(es[index2], 16), phi2)

    plaintext1 = gmpy2.powmod(int(cs[index1], 16), d1, int(ns[index1], 16))
    plaintext2 = gmpy2.powmod(int(cs[index2], 16), d2, int(ns[index2], 16))

    return [binascii.a2b_hex(hex(plaintext1)[2:]), binascii.a2b_hex(hex(plaintext2)[2:])]
#使用费马分解法分解n
def fermat_factorization(n): 
    B = math.factorial(2**14)
    u = 0
    v = 0
    i = 0
    u0 = gmpy2.iroot(n, 2)[0] + 1
    while i <= (B - 1):
        u = (u0 + i)**2 - n
        if gmpy2.is_square(u):
            v = gmpy2.isqrt(u)
            break
        i = i + 1  
    p = u0 + i + v
    return p
#输出费马分解法攻击的结果
def get_content_of_frame10(ns):
    # 分解Frame 10
    n = int(ns[10], 16)
    p = fermat_factorization(n)
    # 已知p，直接计算q和phi(n)
    c = int(cs[10], 16)
    e = int(es[10], 16)
    q = n // p
    phi_n = (p - 1) * (q - 1)
    # 计算私钥d并解密
    d = gmpy2.invert(e, phi_n)
    m = gmpy2.powmod(c, d, n)
    final_plain = binascii.a2b_hex(hex(m)[2:])
    return final_plain
#Pollard p-1分解法攻击
def pollard_p_minus_1_factorization(n):
    b = 2**20
    a = 2
    for i in range(2, b+1):
        a = pow(a, i, n)
        d = gmpy2.gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None
def pollard_resolve(ns,es,cs): 
    index_list = [2, 6, 19]
    plaintexts = []
    for i in index_list:
        n = int(ns[i], 16)
        c = int(cs[i], 16)
        e = int(es[i], 16)
        p = pollard_p_minus_1_factorization(n)
        #print("p of " + str(i) + " is : " + str(p))
        q = n // p
        phi = (p - 1) * (q - 1)
        d = gmpy2.invert(e, phi)
        m = gmpy2.powmod(c, d, n)
        plaintexts.append(binascii.a2b_hex(hex(m)[2:]))
    return plaintexts
# 低加密指数攻击 经过输出检测,发现Frame3,Frame8,Frame12,Frame16,Frame20采用低加密指数e=5进行加密
def chinese_remainder_theorem(items): #中国剩余定理
    N = 1
    for a, n in items:
        N *= n
        result = 0
    for a, n in items:
        m = N//n
        d, r, s = extended_gcd(n, m)
        if d != 1:
            N = N//n
            continue
        result += a*s*m
    return result % N, N
# 低加密指数攻击
def bruce_e_3(ns,cs):
    bruce_range = [7, 11, 15]
    for i in range(3):
        c = int(cs[bruce_range[i]], 16)
        n = int(ns[bruce_range[i]], 16)
        print("This is frame" + str(i))
        for j in range(20):
            plain = gmpy2.iroot(gmpy2.mpz(c+j*n), 3)
            print("This is test" + str(j))
            print(binascii.a2b_hex(hex(plain[0])[2:]))
def low_e_3(ns,cs):
    sessions=[{"c": int(cs[7], 16) ,"n": int(ns[7], 16)},
    {"c":int(cs[11], 16) ,"n":int(ns[11], 16)},
    {"c":int(cs[15], 16) ,"n":int(ns[15], 16)}]
    data = []
    for session in sessions:
        data = data+[(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开三次方根
    plaintext7_11_15 = gmpy2.iroot(gmpy2.mpz(x), 3)
    return binascii.a2b_hex(hex(plaintext7_11_15[0])[2:])
def low_e_5(ns,cs):
    sessions=[{"c": int(cs[3], 16),"n": int(ns[3], 16)},
    {"c":int(cs[8], 16) ,"n":int(ns[8], 16) },
    {"c":int(cs[12], 16),"n":int(ns[12], 16)},
    {"c":int(cs[16], 16),"n":int(ns[16], 16)},
    {"c":int(cs[20], 16),"n":int(ns[20], 16)}]
    data = []
    for session in sessions:
        data = data+[(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开五次方根
    plaintext3_8_12_16_20 = gmpy2.iroot(gmpy2.mpz(x),5)
    return binascii.a2b_hex(hex(plaintext3_8_12_16_20[0])[2:])

if __name__ == '__main__':
    ns=[] #1024bit模数N
    es=[] #1024bit加密指数e
    cs=[] #1024bit密文m^e mod N
    for i in range(21):
        with open("D:/学习/大作业/现代密码学/RSA加密体制破译/密码挑战赛赛题三/附件3-2(发布截获数据)/Frame"+str(i), "r") as f:
            temp = f.read()
            ns.append(temp[0:256])
            es.append(temp[256:512])
            cs.append(temp[512:768])

    result_0=common_modulus_attack(ns,es,cs)
    #print(result_0) # Frame0 与 Frame4 的解密结果是: My secre
    result_1=factor_collision_attack(ns,es,cs)
    #print(result_1[0]) # Frame1解密结果是: . Imagin
    #print(result_1[1]) # Frame18解密结果是: m A to B
    result_2=get_content_of_frame10(ns)
    #print(result_2) # Frame10解密结果是: will get
    result_3=pollard_resolve(ns,es,cs)
    #print(result_3[0]) # Frame2 解密结果是: That is
    #print(result_3[1]) # Frame6 解密结果是: "Logic "
    #print(result_3[2]) # Frame19 解密结果是: instein.
    result_4=low_e_5(ns,cs)
    #print(result_4) ## Frame3 Frame8 Frame12 Frame16 Frame20 解密结果是: t is a f
