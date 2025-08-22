import SparkMD5 from "spark-md5";

const N_FEATURES = 10;
const MISSING = "nan";

/*
 * ממיר טקסט לווקטור של hash md5 עם סימן לפי ה־LSB
 * @param {string[]} parts [finalDomain, sslIssuer, domainRegistrar]
 * @returns {Float32Array} וקטור בגודל 10 עם ערכים מצטברים
 */
export function customMd5HashVector(parts) {
  const vec = new Float32Array(N_FEATURES);

  for (const raw of parts) {
    const str = raw ?? MISSING;

    const hex = SparkMD5.hash(str);
    const bytes = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }

    const intHash = bytes[0] + (bytes[1] << 8) + (bytes[2] << 16) + (bytes[3] << 24) >>> 0;

    const index = intHash % N_FEATURES;
    const sign = (intHash & 1) === 1 ? -1 : 1;

    vec[index] += sign;
  }

  return vec;
}

