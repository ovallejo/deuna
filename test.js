import deuna from 'k6/x/deuna';
import crypto from 'k6/crypto';
import http from "k6/http";

let query = JSON.parse(open('./DataJSON/login.json'))

export default function () {
    const url = '';
    const publicKey = ''
    const epochInSeconds = Math.floor(Date.now() / 1000);
    const username = crypto.sha256('1679114049', 'hex');
    const password = '7Fr0td3AZ'
    query.variables.payload = deuna.encriptar(`{"username":"${username}","password":"${password}","type":"pin"}`, publicKey)
    query.variables.additionalData = deuna.encriptar(`{"deviceId":"0083ee8f-a0b0-467b-9e43-bd252810e979","iat":${epochInSeconds}}`, publicKey);
    const response = http.post(url, JSON.stringify(query), {headers: {'Content-Type': 'application/json'},});
    console.log(response.body)
    console.log(deuna.generarCedula())
    console.log(deuna.getOtp("593931202128"))
    console.log(result)


}

