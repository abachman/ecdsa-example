//
//  ECDSAVerifier.h
//  ecdsa-signature
//
//  Created by Adam Bachman on 3/31/16.
//  Copyright © 2016 Figure 53. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ECDSAVerifier : NSObject

@property NSString *publicKeyPEM;

- (id) initWithPublicKey:(NSString *)keyPEM;

- (void) verifySignature:(NSData*)signature inputData:(NSData*)sourceData;

@property (atomic, assign, readonly ) SecKeyRef     publicKey;

// taken from CryptoCompatibility sample project
@property (atomic, copy,   readonly ) NSError *     error;
@property (atomic, assign, readonly ) BOOL          verified;           // will be NO if self.error not nil

@end
