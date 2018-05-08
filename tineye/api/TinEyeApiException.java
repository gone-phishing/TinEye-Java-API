package tineye.api;


/**
 * @author : Ritesh Kumar Singh
 **/

public class TinEyeApiException extends Exception
{
    /**
     * Construct a <code>TinEyeServiceException</code> with the
     * specified detail message.
     *
     * @param message   The details of the exception. The detail message is
     *                  saved for later retrieval by the Throwable.getMessage() method.
     */
    public TinEyeApiException(String message)
    {
        super(message);
    }

    /**
     * Construct a <code>TinEyeServiceException</code> with the
     * specified detail message and cause.
     *
     * @param message   The details of the exception. The detail message is
     *                  saved for later retrieval by the Throwable.getMessage() method.
     * @param cause     The cause of the exception.
     */
    public TinEyeApiException(String message, Throwable cause)
    {
        super(message, cause);
    }
}