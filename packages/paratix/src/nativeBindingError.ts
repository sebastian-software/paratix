/** Platform or installation failure reported before any secret provider runs. */
export class NativeBindingUnavailableError extends Error {
  public constructor(message: string, options: ErrorOptions) {
    super(message, options)
    this.name = "NativeBindingUnavailableError"
  }
}
