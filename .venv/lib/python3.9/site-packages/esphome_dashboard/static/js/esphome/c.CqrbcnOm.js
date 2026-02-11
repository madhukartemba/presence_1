import{H as o,r as t,b as e,c as n,i as s,k as i,n as a,s as c,x as r,Q as l,J as d,a3 as h}from"./index-D2ez82lt.js";import"./c.poAaLtz1.js";import{c as p,C as u,b as g}from"./c.Cf021qfJ.js";import{s as w}from"./c.BqFZjOdP.js";class m{constructor(){this.chunks=""}transform(o,t){this.chunks+=o;const e=this.chunks.split(/\r?\n/);this.chunks=e.pop(),e.forEach((o=>t.enqueue(`${o}\r\n`)))}flush(o){o.enqueue(this.chunks)}}class f{transform(o,t){const e=new Date,n=e.getHours().toString().padStart(2,"0"),s=e.getMinutes().toString().padStart(2,"0"),i=e.getSeconds().toString().padStart(2,"0");t.enqueue(`[${n}:${s}:${i}]${o}`)}}class _ extends HTMLElement{constructor(){super(...arguments),this.allowInput=!0}logs(){var o;return(null===(o=this._console)||void 0===o?void 0:o.logs())||""}connectedCallback(){if(this._console)return;if(this.attachShadow({mode:"open"}).innerHTML=`\n      <style>\n        :host, input {\n          background-color: #1c1c1c;\n          color: #ddd;\n          font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier,\n            monospace;\n          line-height: 1.45;\n          display: flex;\n          flex-direction: column;\n        }\n        form {\n          display: flex;\n          align-items: center;\n          padding: 0 8px 0 16px;\n        }\n        input {\n          flex: 1;\n          padding: 4px;\n          margin: 0 8px;\n          border: 0;\n          outline: none;\n        }\n        ${p}\n      </style>\n      <div class="log"></div>\n      ${this.allowInput?"<form>\n                >\n                <input autofocus>\n              </form>\n            ":""}\n    `,this._console=new u(this.shadowRoot.querySelector("div")),this.allowInput){const o=this.shadowRoot.querySelector("input");this.addEventListener("click",(()=>{var t;""===(null===(t=getSelection())||void 0===t?void 0:t.toString())&&o.focus()})),o.addEventListener("keydown",(o=>{"Enter"===o.key&&(o.preventDefault(),o.stopPropagation(),this._sendCommand())}))}const o=new AbortController,t=this._connect(o.signal);this._cancelConnection=()=>(o.abort(),t)}async _connect(o){this.logger.debug("Starting console read loop");try{await this.port.readable.pipeThrough(new TextDecoderStream,{signal:o}).pipeThrough(new TransformStream(new m)).pipeThrough(new TransformStream(new f)).pipeTo(new WritableStream({write:o=>{this._console.addLine(o.replace("\r",""))}})),o.aborted||(this._console.addLine(""),this._console.addLine(""),this._console.addLine("Terminal disconnected"))}catch(o){this._console.addLine(""),this._console.addLine(""),this._console.addLine(`Terminal disconnected: ${o}`)}finally{await w(100),this.logger.debug("Finished console read loop")}}async _sendCommand(){const o=this.shadowRoot.querySelector("input"),t=o.value,e=new TextEncoder,n=this.port.writable.getWriter();await n.write(e.encode(`${t}\r\n`)),this._console.addLine(`> ${t}\r\n`),o.value="",o.focus();try{n.releaseLock()}catch(o){console.error("Ignoring release lock error",o)}}async disconnect(){this._cancelConnection&&(await this._cancelConnection(),this._cancelConnection=void 0)}async reset(){this.logger.debug("Triggering reset."),await this.port.setSignals({dataTerminalReady:!1,requestToSend:!0}),await this.port.setSignals({dataTerminalReady:!1,requestToSend:!1}),await new Promise((o=>setTimeout(o,1e3)))}}customElements.define("ewt-console",_);let y=class extends c{constructor(){super(...arguments),this._isPico=!1}render(){return r`
      <mwc-dialog
        open
        .heading=${this.configuration?`Logs ${this.configuration}`:"Logs"}
        scrimClickAction
        @closed=${this._handleClose}
      >
        <ewt-console
          .port=${this.port}
          .logger=${console}
          .allowInput=${!1}
        ></ewt-console>
        <mwc-button
          slot="secondaryAction"
          label="Download Logs"
          @click=${this._downloadLogs}
        ></mwc-button>
        ${this.configuration?r`
              <mwc-button
                slot="secondaryAction"
                dialogAction="close"
                label="Edit"
                @click=${this._openEdit}
              ></mwc-button>
            `:""}
        ${this._isPico?"":r`
              <mwc-button
                slot="secondaryAction"
                label="Reset Device"
                @click=${this._resetDevice}
              ></mwc-button>
            `}
        <mwc-button
          slot="primaryAction"
          dialogAction="close"
          label="Close"
        ></mwc-button>
      </mwc-dialog>
    `}firstUpdated(o){super.firstUpdated(o),this.configuration&&l(this.configuration).then((o=>{this._isPico="RP2040"===o.esp_platform}))}async _openEdit(){this.configuration&&d(this.configuration)}async _handleClose(){await this._console.disconnect(),this.closePortOnClose&&await this.port.close(),this.parentNode.removeChild(this)}async _resetDevice(){await this._console.reset()}_downloadLogs(){h(this._console.logs(),(this.configuration?`${g(this.configuration)}_logs`:"logs")+".txt")}};y.styles=[o,t`
      mwc-dialog {
        --mdc-dialog-max-width: 90vw;
      }
      ewt-console {
        width: calc(80vw - 48px);
        height: calc(90vh - 128px);
      }
    `],e([n()],y.prototype,"configuration",void 0),e([n()],y.prototype,"port",void 0),e([n()],y.prototype,"closePortOnClose",void 0),e([s("ewt-console")],y.prototype,"_console",void 0),e([i()],y.prototype,"_isPico",void 0),y=e([a("esphome-logs-webserial-dialog")],y);
//# sourceMappingURL=c.CqrbcnOm.js.map
