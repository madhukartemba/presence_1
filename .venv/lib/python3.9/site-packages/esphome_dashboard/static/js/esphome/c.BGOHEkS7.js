import{H as t,r as o,b as e,c as s,k as i,n,s as a,x as r,J as l}from"./index-D2ez82lt.js";import"./c.Cf021qfJ.js";import{o as c}from"./c.Cz-na1C9.js";import"./c.poAaLtz1.js";let h=class extends a{render(){return r`
      <esphome-process-dialog
        .heading=${`Install ${this.configuration}`}
        .type=${"run"}
        .spawnParams=${{configuration:this.configuration,port:this.target}}
        @closed=${this._handleClose}
        @process-done=${this._handleProcessDone}
      >
        ${"OTA"===this.target?"":r`
              <a
                href="https://esphome.io/guides/faq.html#i-can-t-get-flashing-over-usb-to-work"
                slot="secondaryAction"
                target="_blank"
                >❓</a
              >
            `}
        <mwc-button
          slot="secondaryAction"
          dialogAction="close"
          label="Edit"
          @click=${this._openEdit}
        ></mwc-button>
        ${void 0===this._result||0===this._result?"":r`
              <mwc-button
                slot="secondaryAction"
                dialogAction="close"
                label="Retry"
                @click=${this._handleRetry}
              ></mwc-button>
            `}
      </esphome-process-dialog>
    `}_openEdit(){l(this.configuration)}_handleProcessDone(t){this._result=t.detail}_handleRetry(){c(this.configuration,this.target)}_handleClose(){this.parentNode.removeChild(this)}};h.styles=[t,o`
      a[slot="secondaryAction"] {
        text-decoration: none;
        line-height: 32px;
      }
    `],e([s()],h.prototype,"configuration",void 0),e([s()],h.prototype,"target",void 0),e([i()],h.prototype,"_result",void 0),h=e([n("esphome-install-server-dialog")],h);
//# sourceMappingURL=c.BGOHEkS7.js.map
