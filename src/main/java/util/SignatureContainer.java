package util;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignatureContainer {

    String signature;
    String algorithm;

    String certStr;

    public String getCertStr() {
        return certStr;
    }

    public void setCertStr(String certStr) {
        this.certStr = certStr;
    }



    @JsonProperty
    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    @JsonProperty
    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
}
