import{H as e,r as t,b as o,c as a,n as i,s as n,x as l,G as s,g as c}from"./index-D2ez82lt.js";import"./c.poAaLtz1.js";let r=class extends n{render(){return l`
      <mwc-dialog
        .heading=${`Delete ${this.name}`}
        @closed=${this._handleClose}
        open
      >
        <div>Are you sure you want to delete ${this.name}?</div>
        <mwc-button
          slot="primaryAction"
          class="warning"
          label="Delete"
          dialogAction="close"
          @click=${this._handleDelete}
        ></mwc-button>
        <mwc-button
          slot="secondaryAction"
          no-attention
          label="Cancel"
          dialogAction="cancel"
        ></mwc-button>
      </mwc-dialog>
    `}_handleClose(){this.parentNode.removeChild(this)}async _handleDelete(){await s(this.configuration),c(this,"deleted")}};r.styles=[e,t`
      .warning {
        --mdc-theme-primary: var(--alert-error-color);
      }
    `],o([a()],r.prototype,"name",void 0),o([a()],r.prototype,"configuration",void 0),r=o([i("esphome-delete-device-dialog")],r);
//# sourceMappingURL=c.DcZacTgB.js.map
