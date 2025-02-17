import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import style from "./styles/footer.scss"
import { version } from "../../package.json"
import { i18n } from "../i18n"
import { useEffect } from "react"

interface Options {
  links: Record<string, string>
}

export default ((opts?: Options) => {
  const Footer: QuartzComponent = ({ displayClass, cfg }: QuartzComponentProps) => {
    const year = new Date().getFullYear()
    const links = opts?.links ?? []

    useEffect(() => {
      // Evitar duplicados
      if (!document.querySelector('script[data-name="BMC-Widget"]')) {
        const script = document.createElement("script")
        script.setAttribute("data-name", "BMC-Widget")
        script.setAttribute("data-cfasync", "true")
        script.src = "https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js"
        script.setAttribute("data-id", "gitblanc")
        script.setAttribute("data-description", "Support me on Buy me a coffee!")
        script.setAttribute("data-message", "")
        script.setAttribute("data-color", "#F44336")
        script.setAttribute("data-position", "Right")
        script.setAttribute("data-x_margin", "18")
        script.setAttribute("data-y_margin", "18")
        document.body.appendChild(script)
      }
    }, []) // Se ejecuta solo una vez al montar el componente

    return (
      <footer class={`${displayClass ?? ""}`}>
        <hr />
        <h2 id="how-is-this-page">Comments</h2>
        <script
          src="https://utteranc.es/client.js"
          repo="gitblanc/c1b3rn0t3s"
          issue-term="pathname"
          label="Comments"
          theme="github-dark"
          crossOrigin="anonymous"
          async
        ></script>
        <p>
          {i18n(cfg.locale).components.footer.createdWith}{" "}
          <a href="https://quartz.jzhao.xyz/">Quartz v{version}</a> © {year}
        </p>
        <ul>
          {Object.entries(links).map(([text, link]) => (
            <li key={text}>
              <a href={link}>{text}</a>
            </li>
          ))}
        </ul>
      </footer>
    )
  }

  Footer.css = style
  return Footer
}) satisfies QuartzComponentConstructor
