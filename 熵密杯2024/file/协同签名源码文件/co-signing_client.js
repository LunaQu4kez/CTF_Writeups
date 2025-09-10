const form = ref({
    password: "",
    msgdigest: "",
})

const k1: any = ref("");

const submit = () => {
    isform.value.validate((valid: boolean) => {
        if (valid) {
            
            loading.value = true;
            let smPassword = ref("");
            smPassword.value = sm3(form.value.password);
            // 客户端通过用户口令、消息摘要和用户私钥d1，计算客户端协同签名值 p1x, p1y, q1x, q1y, r1, s1
            var { str_e, str_p1x, str_p1y, str_q1x, str_q1y, str_r1, str_s1, errMessage } = clientSign1(smPassword.value, form.value.msgdigest);
            if (errMessage) {
                ElMessage.error(errMessage)
                loading.value = false;
                return
            }
            let data = {
                q1x: str_q1x,
                q1y: str_q1y,
                e: str_e,
                r1: str_r1,
                s1: str_s1,
                p1x: str_p1x,
                p1y: str_p1y
            }
            // 客户端将 e, p1x, p1y, q1x, q1y, r1, s1发送给服务端
            // 服务端用服务端私钥d2计算服务端协同签名值 s2, s3, r 发送给客户端
            sign_param_send(data).then((res: any) => {
                // 客户端通过s2, s3, r，计算协同签名值 s
                let str_s: any = clientSign2(smPassword.value, res.s2, res.s3, res.r);
                if (str_s.errMessage) {
                    ElMessage.error(errMessage)
                    loading.value = false;
                    return
                }
                ElMessage.success("协同签名成功");
                signature_send({ client_sign: str_s }).then((res: any) => {
                    qmz.value = str_s;
                    loading.value = false;
                }).then((err: any) => {
                    loading.value = false;
                })
            }).catch((err: any) => {
                loading.value = false;
            })
        }
    })
}
const clientSign1: any = (str_d1: any, str_e: any) => {
    let d1 = new BN(str_d1, 16);
    // console.log("e",str_e)
    
    let e = new BN(str_e, 16);
    // console.log("e",e)
    const sm2: any = new elliptic.curve.short({
        p: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
        a: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
        b: '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
        n: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
        g: [
            '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7',
            'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'
        ]
    } as any);

    let n = new BN(sm2.n.toString(16), 16);    
    let G = sm2.g;

    // generate random k1
    const randomBytes = cryptoRandomStringAsync({ length: 64 });
    k1.value = new BN(randomBytes as any, 16);
    while(k1.value.mod(n).isZero()){
        const randomBytes = cryptoRandomStringAsync({ length: 64 });
        k1.value = new BN(randomBytes as any, 16);     
    }
    k1.value = k1.value.mod(n);

    // d1 = d1 mod n
    d1 = d1.mod(n);
    if (d1.isZero()) {
        let errMessage = "d1=0，签名失败"
        return { errMessage }
    }

    //P1 = ((d1)^(-1)) * G
    let tmp1 = d1.invm(n);
    let P1 = G.mul(tmp1);

    //Q1 = k1*G = (x, y)
    let Q1 = G.mul(k1.value);
    let x = new BN(Q1.getX().toString(16), 16);

    //r1 = x mod n
    let r1 = x.mod(n);
    if (r1.isZero()) {
        let errMessage = "r1=0，签名失败"
        return { errMessage }
    }

    //s1 = k1^(-1) * (e + d1^(-1) * r1) mod n
    tmp1 = d1.invm(n);
    let tmp2 = tmp1.mul(r1).mod(n);
    let tmp3 = tmp2.add(e).mod(n);
    tmp1 = k1.value.invm(n);
    let s1 = tmp1.mul(tmp3).mod(n);
    if (s1.isZero()) {
        let errMessage = "s1=0，签名失败"
        return { errMessage }
    }

    str_e = e.toString(16);
    // console.log("str_e",str_e)
    let str_p1x = P1.getX().toString(16);
    let str_p1y = P1.getY().toString(16);
    let str_q1x = Q1.getX().toString(16);
    let str_q1y = Q1.getY().toString(16);
    let str_r1 = r1.toString(16);
    let str_s1 = s1.toString(16);
    return { str_e, str_p1x, str_p1y, str_q1x, str_q1y, str_r1, str_s1 }
}
const clientSign2 = (str_d1: any, str_s2: any, str_s3: any, str_r: any) => {
    const sm2 = new elliptic.curve.short({
        p: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
        a: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
        b: '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
        n: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
        g: [
            '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7',
            'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'
        ]
    } as any);

    let d1 = new BN(str_d1, 16);
    let n = new BN(sm2.n.toString(16), 16);
    let s2 = new BN(str_s2, 16);
    let s3 = new BN(str_s3, 16);
    let r = new BN(str_r, 16);
    //s = d1*k1*s2 + d1*s3 -r mod n
    let tmp1 = d1.mul(k1.value).mod(n);
    let tmp2 = tmp1.mul(s2).mod(n);
    let tmp3 = d1.mul(s3).mod(n);
    tmp1 = tmp2.add(tmp3).mod(n);
    let s = tmp1.sub(r).mod(n);
    if (s.isZero()) {
        let errMessage = "s=0，签名失败"
        return { errMessage }
    }
    if (s.add(r).mod(n).isZero()) {
        let errMessage = "s=n-r，签名失败"
        return { errMessage }
    }
    let str_s = s.toString(16);
    if (str_s[0] == '-') {
        s = s.add(n).mod(n);
        str_s = s.toString(16);
    }
    return str_s;
}