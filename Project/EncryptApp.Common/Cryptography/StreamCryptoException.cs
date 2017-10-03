using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace EncryptApp.Cryptography
{
    [Serializable]
    public class StreamCryptoException : Exception
    {
        public StreamCryptoError Error { get; private set; }

        public StreamCryptoException(StreamCryptoError error, string message)
            : base(message)
        {
            this.Error = error;
        }

        public StreamCryptoException(StreamCryptoError error, string message, Exception exc)
            : base(message, exc)
        {
            this.Error = error;
        }

        protected StreamCryptoException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }
}
