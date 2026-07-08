/*
 * Standard OpenKeychain / openpgp-api interface (IOpenPgpService2).
 * Client-side executeApi / executeApiAsync live in org.openintents.openpgp.util.OpenPgpApi.
 */
package org.openintents.openpgp;

interface IOpenPgpService2 {

    /**
     * Returns the read end of an output pipe; the service keeps the write end until execute() finishes.
     */
    ParcelFileDescriptor createOutputPipe(in int pipeId);

    /**
     * Performs the OpenPGP operation described by data; streams input/output via pipeId when set.
     */
    Intent execute(in Intent data, in ParcelFileDescriptor input, int pipeId);
}
