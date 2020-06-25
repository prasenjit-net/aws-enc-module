'use strict';
const aws = require('aws-sdk');
const crypto = require('crypto');

exports.KmsCrypto = {
    encryptedDataKey: null,
    hashedPassword: null,
    savedSalt: null,
    keyId: null,
    kms: new aws.KMS({
        region: 'us-east-1',
    }),
    generateKey: function (password, kmsKeyArn, salt) {
        this.keyId = kmsKeyArn;
        this.savedSalt = Buffer.from(salt);
        let req = {
            KeySpec: "AES_256",
            KeyId: this.keyId
        };
        return new Promise((resolve, reject) => {
            this.kms.generateDataKey(req).promise()
                .then(data => {
                    this.encryptedDataKey = data.CiphertextBlob;
                    this.hashedPassword = crypto.createHmac('sha256', data.Plaintext)
                        .update(password).update(this.savedSalt).digest('base64');

                    console.log('Encrypted Key:', this.encryptedDataKey.toString('base64'));
                    console.log('Hashed Password:', this.hashedPassword);
                    console.log('Salt:', this.savedSalt.toString('base64'));
                    resolve(this);
                }).catch(err => {
                console.log('Error creating data key', err);
                reject(err);
            });
        });
    },
    validatePassword: function (inputPassword) {
        let req = {
            CiphertextBlob: this.encryptedDataKey,
            KeyId: this.keyId
        };
        return this.kms.decrypt(req).promise()
            .then(data => {
                let inputPasswordHash = crypto.createHmac('sha256', data.Plaintext)
                    .update(inputPassword).update(this.savedSalt).digest('base64');

                if (this.hashedPassword === inputPasswordHash) {
                    console.log('Password is a match for:', inputPassword);
                } else {
                    console.log('Password doesnt match for:', inputPassword);
                }
            })
            .catch(err => {
                console.log('Failed to decrypt key', err);
            });
    }
};