using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Jose;

namespace Certificate.POC;

internal class Program
{
    static void Main(string[] args)
    {
        // var pkcs10 = CreateCSR("Foo");

        var key = RSA.Create();
        key.ImportFromPem(File.ReadAllText("./Resources/privKey.pem"));

        var publicKey = RSA.Create();
        publicKey.ImportFromPem(File.ReadAllText("./Resources/pubKey.pem"));
        var payload = JsonSerializer.Serialize(new { Foo = "Bar" });

        // RSASSA-PSS: probabilistic signature
        var signature_1 = Sign(payload, key, JwsAlgorithm.PS256);
        var signature_2 = Sign(payload, key, JwsAlgorithm.PS256);
        Debug.Assert(signature_1 != signature_2);
        Debug.Assert(Verify(signature_1, payload, publicKey, JwsAlgorithm.PS256));
        Debug.Assert(Verify(signature_2, payload, publicKey, JwsAlgorithm.PS256));

        // RSASSA-PKCS1-v1_5: deterministic signature
        var signature_3 = Sign(payload, key, JwsAlgorithm.RS256);
        var signature_4 = Sign(payload, key, JwsAlgorithm.RS256);
        Debug.Assert(signature_3 == signature_4);
        Debug.Assert(Verify(signature_3, payload, publicKey, JwsAlgorithm.RS256));
        Debug.Assert(Verify(signature_4, payload, publicKey, JwsAlgorithm.RS256));
    }

    /// <summary>
    /// <para>-----BEGIN CERTIFICATE REQUEST-----</para>
    /// <para>MIIBW...</para>
    /// <para>-----END CERTIFICATE REQUEST-----</para>
    /// </summary>
    /// <param name="subjectName"></param>
    /// <param name="keySize"></param>
    /// <returns></returns>
    static string CreateCSR(string subjectName, int keySize = 2048)
    {
        var key = RSA.Create(keySize);
        var request = new CertificateRequest(
            subjectName: $"CN={subjectName}",
            key: key,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1
        );
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var csr = request.CreateSigningRequest();
        //https://www.rfc-editor.org/rfc/rfc7468#section-7
        //Textual Encoding of PKCS #10 Certification Request Syntax
        var csrBs64Pem = PemEncoding.Write("CERTIFICATE REQUEST", csr);

        return new string(csrBs64Pem);
    }

    static string Sign(string payload, object key, JwsAlgorithm algorithm)
    {
        return JWT.Encode(payload, key, algorithm, options: new JwtOptions()
        {
            EncodePayload = true,
            DetachPayload = true
        });
    }

    static bool Verify(string signature, string payload, object key, JwsAlgorithm algorithm)
    {
        JWT.Decode(signature, key, algorithm, null, payload);
        return true;
    }
}