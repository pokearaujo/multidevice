import { Binary } from '../proto/Binary';
import { Socket } from './Socket';

export class FrameSocket {
    private socket: Socket;
    private incoming = new Binary();
    private closed = false;
    private draining = false;
    public onFrame = null;
    public onClose = null;

    private introToSend: Uint8Array = null;

    constructor(socket: Socket, introToSend: Uint8Array) {
        this.incoming = new Binary();
        this.closed = false;
        this.draining = false;
        this.onFrame = null;
        this.onClose = null;

        this.introToSend = introToSend;
        this.socket = socket;

        socket.onData = this.handleData.bind(this);
        socket.onClose = this.handleClose.bind(this);
        socket.onError = this.handleError.bind(this);
    }

    public sendFrame(data: Uint8Array) {
        if (this.draining) {
            return;
        }

        this.throwIfClosed();

        const size = data.byteLength;
        const introSize = this.introToSend ? this.introToSend.length : 0;

        this.socket.dataToSend.ensureAdditionalCapacity(introSize + 3 + size);

        if (this.introToSend) {
            this.socket.dataToSend.writeByteArray(this.introToSend);
            this.introToSend = null;
        }

        this.socket.dataToSend.writeUint8(size >> 16);
        this.socket.dataToSend.writeUint16(65535 & size);
        this.socket.dataToSend.write(data);

        return this.socket.requestSend();
    }

    public throwIfClosed() {
        if (this.closed) {
            throw new Error('closed');
        }
    }

    public close() {
        this.socket.close();
    }

    public restart() {
        this.socket.restart();
    }

    public convertBufferedToFrames() {
        let currFrame = this.onFrame;
        let currIncoming = this.incoming;

        for (; currFrame && currIncoming.peek(this.peekSize.bind(this)); ) {
            const bytes = this.getBytesSize(currIncoming);
            //console.log(`FrameSocket.onFrame(${bytes} bytes)`);

            currFrame(currIncoming.readByteArray(bytes));

            currFrame = this.onFrame;
        }

        if (this.draining && currIncoming.peek(this.peekSize.bind(this))) {
            this.doClose();
        }

        if (currFrame && currIncoming.size()) {
            console.log(`FrameSocket: queueing partial frame of ${currIncoming.size()} bytes`)
        }
    }

    private doClose() {
        if (!this.closed) {
            console.log('FrameSocket closed');

            this.draining = false;
            this.closed = true;
            this.onClose && this.onClose();

            console.log("Trying restart when framesocket closed");
            this.socket.restart();
        }
    }

    private handleData(data: Uint8Array) {
        this.incoming.writeByteArray(data);
        this.convertBufferedToFrames();
    }

    private handleClose() {
        if (this.incoming.peek(this.peekSize.bind(this))) {
            console.log('FrameSocket closed, waiting for pending processing');

            this.draining = true;
            return;
        }

        this.doClose();
    }

    private handleError(e) {
        console.log('frame socket error', e);
    }

    private getBytesSize(data: Binary) {
        return (data.readUint8() << 16) | data.readUint16();
    }

    private peekSize(data: Binary) {
        return !(data.size() < 3) && this.getBytesSize(data) <= data.size();
    }
}
