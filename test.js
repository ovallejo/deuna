import deuna from 'k6/x/deuna';


export default function () {
    const message = deuna.encriptar('{"deviceId":"62ddf5e8-5721-404a-a954-9bd374d88d76","iat":1698556103}',
        '');
    console.log(message)
}

