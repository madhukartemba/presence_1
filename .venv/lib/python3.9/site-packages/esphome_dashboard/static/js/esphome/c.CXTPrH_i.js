import{H as o,r as t,b as e,c as s,k as i,n as r,s as a,x as n}from"./index-D2ez82lt.js";import"./c.Cf021qfJ.js";import{o as l,a as c}from"./c.iaQntAtS.js";import"./c.poAaLtz1.js";import"./c.DaYIS3VI.js";import"./c.C_NgdYHj.js";import"./c.B2VAPQQR.js";import"./c.BTkMKd_p.js";import"./c.Cz-na1C9.js";let p=class extends a{constructor(){super(...arguments),this.downloadFactoryFirmware=!0}render(){return n`
      <esphome-process-dialog
        .heading=${`Download ${this.configuration}`}
        .type=${"compile"}
        .spawnParams=${{configuration:this.configuration}}
        @closed=${this._handleClose}
        @process-done=${this._handleProcessDone}
      >
        ${void 0===this._result?"":0===this._result?n`
                <mwc-button
                  slot="secondaryAction"
                  label="Download"
                  @click=${this._handleDownload}
                ></mwc-button>
              `:n`
                <mwc-button
                  slot="secondaryAction"
                  dialogAction="close"
                  label="Retry"
                  @click=${this._handleRetry}
                ></mwc-button>
              `}
      </esphome-process-dialog>
    `}_handleProcessDone(o){this._result=o.detail,0===o.detail&&l(this.configuration,this.platformSupportsWebSerial)}_handleDownload(){l(this.configuration,this.platformSupportsWebSerial)}_handleRetry(){c(this.configuration,this.platformSupportsWebSerial)}_handleClose(){this.parentNode.removeChild(this)}};p.styles=[o,t`
      a {
        text-decoration: none;
      }
    `],e([s()],p.prototype,"configuration",void 0),e([s()],p.prototype,"platformSupportsWebSerial",void 0),e([s()],p.prototype,"downloadFactoryFirmware",void 0),e([i()],p.prototype,"_result",void 0),p=e([r("esphome-compile-dialog")],p);
//# sourceMappingURL=c.CXTPrH_i.js.map
