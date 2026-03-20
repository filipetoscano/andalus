using Andalus.Cryptography.Xml.Algorithms;
using System.Security.Cryptography.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary />
public static class Extensions
{
    /// <summary />
    public static string ToAlgorithmUrl( this XmlCanonicalization value )
    {
        return value switch
        {
            XmlCanonicalization.XmlDsigC14NTransform => SignedXml.XmlDsigC14NTransformUrl,
            XmlCanonicalization.XmlDsigC14NWithCommentsTransform => SignedXml.XmlDsigC14NWithCommentsTransformUrl,
            XmlCanonicalization.XmlDsigC14N11Transform => XmlDsigC14N11Transform.AlgorithmUri,
            XmlCanonicalization.XmlDsigC14N11WithCommentsTransform => XmlDsigC14N11WithCommentsTransform.AlgorithmUri,
            XmlCanonicalization.XmlDsigExcC14NTransform => SignedXml.XmlDsigExcC14NTransformUrl,
            XmlCanonicalization.XmlDsigExcC14NWithCommentsTransform => SignedXml.XmlDsigExcC14NWithCommentsTransformUrl,

            _ => throw new NotSupportedException(),
        };
    }
}