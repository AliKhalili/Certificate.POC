using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Certificate.POC;

internal class Program
{
    static void Main(string[] args)
    {
        var pkcs10 = CreateCSR("Foo");
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
}