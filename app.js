'use strict';
const KmsCrypto = require('./generate');


const generatorKeyId = 'arn:aws:kms:us-east-1:176420475895:key/2e26d138-4dbb-491b-944b-f53ed8257fb2';
KmsCrypto.KmsCrypto.generateKey('password', generatorKeyId, 'salt').then((data) => {
        data.validatePassword('password');
        data.validatePassword('not same');
    }
);