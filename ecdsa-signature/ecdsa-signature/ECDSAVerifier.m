//
//  ECDSAVerifier.m
//  ecdsa-signature
//
//  Created by Adam Bachman on 3/31/16.
//  Copyright © 2016 Figure 53. All rights reserved.
//

#import "ECDSAVerifier.h"

@interface ECDSAVerifier ()

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSError *     error;
@property (atomic, assign, readwrite) BOOL          verified;

@end

@implementation ECDSAVerifier

- (id) initWithPublicKey:(NSString *)keyPEM
{
    self = [super init];
    if (self != nil) {
        self.publicKeyPEM = keyPEM;
        [self parsePublicKey];
    }
    return self;
}

- (void) parsePublicKey
{
    
    SecKeyRef publicKey;
    
    CFDataRef publicKeyData = CFBridgingRetain([self.publicKeyPEM dataUsingEncoding: NSUTF8StringEncoding]);
    
    // Turning our public key in PEM form into SecKeyRef.
    SecExternalFormat   externalFormat   = kSecFormatPEMSequence;
    SecExternalItemType externalItemType = kSecItemTypePublicKey;
    
    SecItemImportExportKeyParameters itemImportExportKeyParameters;
    itemImportExportKeyParameters.keyUsage = NULL;
    itemImportExportKeyParameters.keyAttributes = NULL;
    
    // Convert PEM public key to SecKeyRef
    CFArrayRef tempArray;
    
    // Add public key to tempArray
    OSStatus status = SecItemImport(publicKeyData, NULL, &externalFormat, &externalItemType, 0, &itemImportExportKeyParameters, NULL, &tempArray);
    
    if (status != 0) {
        NSLog(@"failed to parse public key <OSStatus error %d>", status);
        switch (status) {
            case errSecUnknownFormat:
                NSLog(@"public key is in an unrecognized format");
                break;
        }
        exit(-1);
    }
    
    // Getting SecKeyRef from the array and retaining it.
    publicKey = (SecKeyRef)CFRetain(CFArrayGetValueAtIndex(tempArray, 0));
    
    // Cleanup
    CFRelease(publicKeyData);
    CFRelease(tempArray);
    
    // Store public key
    CFRetain(publicKey);
    self->_publicKey = publicKey;
}

// Verify the given signature against the given input data. State
// of ECDSAVerifier will be updated when verification is complete.
- (void) verifySignature:(NSData*)signatureData64 inputData:(NSData*)inputData
{
    // These parameters are mandatory.
    NSParameterAssert(signatureData64);
    NSParameterAssert(inputData);
    
    // Make sure developer didn't forget to set the public key.
    NSAssert(self.publicKey,    @"DSA/ECDSA public key is not set.");
    
    BOOL            success = NO;
    CFBooleanRef    result = NULL;
    CFErrorRef      errorCF = NULL;
    SecTransformRef transform = NULL;
    
    // Decode signature data from Base64
    NSData *sigDecoded = [[NSData alloc] initWithBase64EncodedData:signatureData64 options:0];
    CFDataRef signature = (__bridge CFDataRef)sigDecoded;
    success = (signature != NULL);
    
    if (success) {
        // initialize the validation transform operation
        transform = SecVerifyTransformCreate(self.publicKey, signature, &errorCF);
        success = (transform != NULL);
    } else {
        NSLog(@"FAILURE before initializing transform");
    }
    
    if (errorCF != NULL) { NSLog(@"errorCF is not null after creating Transform"); }
    
    // Add a SHA-2 Digest with length of 256
    if (success)
    {
        success = SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA2, &errorCF) != false;
        success = SecTransformSetAttribute(transform, kSecDigestLengthAttribute, (__bridge CFNumberRef)@256, &errorCF);
    } else {
        NSLog(@"FAILURE before attempting to set transform digest type attribute");
    }
    
    if (errorCF != NULL) { NSLog(@"errorCF is not null after preparing digest"); }
    
    if (success)
    {
        success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, (__bridge CFDataRef)inputData, &errorCF);
    } else {
        NSLog(@"FAILURE before setting input data");
    }
    if (errorCF != NULL) { NSLog(@"errorCF is not null after setting input data"); }
    
    if (success) {
        result = SecTransformExecute(transform, &errorCF);
        success = (result != NULL);
    } else {
        NSLog(@"FAILURE executing transform");
    }
    
    if (errorCF != NULL) { NSLog(@"errorCF is not null after executing"); }
    
    // Process the results.
    
    if (success) {
        assert(CFGetTypeID(result) == CFBooleanGetTypeID());
        self.verified = (CFBooleanGetValue(result) != false);
    } else {
        // If verification was *not* successful, an error MUST have been provided.
        assert(errorCF != NULL);
        self.error = (__bridge NSError *) errorCF;
    }
    
    // Final cleanup
    
    if (signature != NULL) {
        CFRelease(signature);
    }
    if (result != NULL) {
        CFRelease(result);
    }
    if (errorCF != NULL) {
        CFRelease(errorCF);
    }
    if (transform != NULL) {
        // FIXME: this is included in example code, but blows up if it runs here
        // CFRelease(transform);
    }
}


@end
