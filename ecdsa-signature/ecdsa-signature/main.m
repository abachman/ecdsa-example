//
//  main.m
//  ecdsa-signature
//
//  Demonstrate ECDSA signature verification using Apple's provided security libraries.
//
//  Created by Adam Bachman on 3/31/16.
//  Copyright © 2016 Figure 53. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ECDSAVerifier.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *keyPEM;
        
        // Parse arguments
        NSUserDefaults* arguments = [NSUserDefaults standardUserDefaults];
        
        // load key from file
        if ([arguments objectForKey:@"key"])
        {
            NSString *keyFilePath = [arguments stringForKey:@"key"];
            
            NSFileManager *fileManager = [NSFileManager defaultManager];
            if ([fileManager fileExistsAtPath:keyFilePath])
            {
                NSData* data = [NSData dataWithContentsOfFile:keyFilePath];
                keyPEM = [[NSString alloc] initWithBytes:[data bytes]
                                                  length:[data length]
                                                encoding:NSUTF8StringEncoding];
                
                NSLog(@"loading key file from %@", [arguments stringForKey:@"key"]);
                NSLog(@"%@", keyPEM);
            }
        }
        
        // use default
        if (keyPEM == nil)
        {
            NSMutableString *key = [NSMutableString string];
            // KNOWN GOOD
            [key appendString:@"-----BEGIN PUBLIC KEY-----\n"];
            [key appendString:@"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE9RvMT/UllobApQ2fniSI4qv28Os0wAPn\n"];
            [key appendString:@"OBazp+tMsrHL4FRWhmFpZ9abTST7quvtcItleFBXWJN2l9u6dwnL39PjZpTpA2op\n"];
            [key appendString:@"YZmBDjqXp/uE7g0w37CQRt98VS8zdciB\n"];
            [key appendString:@"-----END PUBLIC KEY-----"];
            // // KNOWN BAD
            // [key appendString:@"----BEGIN PUBLIC KEY-----"];
            // [key appendString:@"FYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnqSMGVn/KxMUViXsdcv05zjqYV5cK8R/"];
            // [key appendString:@"PPZvHvjIpfEDrO2af2oBNAtbnhSLTXv5imwZ0xrutqqWvXE4LqZcA=="];
            // [key appendString:@"----END PUBLIC KEY-----"];
            keyPEM = [NSString stringWithString:key];
        }   
        
        ECDSAVerifier *verifier = [[ECDSAVerifier alloc] initWithPublicKey:keyPEM];
        
        NSString *signatureString64 = @"MGQCMCAvFBsqplvhiZHn0sMkBBtYFD8cG8uqF0HrXsgBcZTdPlhutdUt68xuH7dIG+OT2QIwa3oTkIITVelHoCowfrnDJ57mhxIEWjGrEDY4jjHNXslBhReSUnGAYwecWx6uFvfX";
        NSString *dataString = @"5717ed168d23155cb923ea2bba4f01e93e2ea9373ebb778d645a0c4c1a17fbb31e90731f12eaa441396680c8d571674e219c753dec9687c127bdcbcb863dcb5715";
        
        NSData *signature64 = [signatureString64 dataUsingEncoding:NSUTF8StringEncoding];
        NSData *data = [dataString dataUsingEncoding:NSUTF8StringEncoding];
        
        [verifier verifySignature:signature64 inputData:data];
        
        // check error status
        if (verifier.error) {
            NSLog(@"THE SIGNATURE IS INVALID AND THERE WAS AN ERROR");
            NSLog(@"%@", verifier.error);
            return 1;
        }
        
        // check verification status
        if (verifier.verified) {
            NSLog(@"the signature is valid");
        } else {
            NSLog(@"THE SIGNATURE IS INVALID");
            return 1;
        }
    }
    
    return 0;
}

