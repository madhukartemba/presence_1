import{H as o,b as t,c as i,k as s,n as e,s as a,x as n,J as l,h as c}from"./index-D2ez82lt.js";import"./c.Cf021qfJ.js";import"./c.poAaLtz1.js";let d=class extends a{render(){const o=void 0===this._valid?"":this._valid?"✅":"❌";return n`
      <esphome-process-dialog
        .heading=${`Validate ${this.configuration} ${o}`}
        .type=${"validate"}
        .spawnParams=${{configuration:this.configuration}}
        @closed=${this._handleClose}
        @process-done=${this._handleProcessDone}
      >
        <mwc-button
          slot="secondaryAction"
          dialogAction="close"
          label="Edit"
          @click=${this._openEdit}
        ></mwc-button>
        <mwc-button
          slot="secondaryAction"
          dialogAction="close"
          label="Install"
          @click=${this._openInstall}
        ></mwc-button>
      </esphome-process-dialog>
    `}_openEdit(){l(this.configuration)}_openInstall(){c(this.configuration)}_handleProcessDone(o){this._valid=0==o.detail}_handleClose(){this.parentNode.removeChild(this)}};d.styles=[o],t([i()],d.prototype,"configuration",void 0),t([s()],d.prototype,"_valid",void 0),d=t([e("esphome-validate-dialog")],d);
//# sourceMappingURL=c.C0mpVxlK.js.map
