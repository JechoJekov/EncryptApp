using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace EncryptApp.Loader
{
    [Serializable]
    public class ApplicationLoaderException : Exception
    {
        public ApplicationLoaderException() { }
        public ApplicationLoaderException(string message) : base(message) { }
        public ApplicationLoaderException(string message, Exception inner) : base(message, inner) { }
        protected ApplicationLoaderException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}
