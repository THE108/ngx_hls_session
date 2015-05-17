#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static u_char m3u8_content_type[] = "application/vnd.apple.mpegurl";

static char *ngx_http_hello(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_handler_pt ngx_http_hello_p = ngx_http_hello;

/*
 * The structure will holds the value of the 
 * module directive hello
 */
typedef struct {
    ngx_str_t   name;
} ngx_http_hello_loc_conf_t;

/* The function which initializes memory for the module configuration structure       
 */
static void *
ngx_http_hello_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hello_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    
    return conf;
}

/* 
 * The command array or array, which holds one subarray for each module 
 * directive along with a function which validates the value of the 
 * directive and also initializes the main handler of this module
 */
static ngx_command_t ngx_http_hello_commands[] = {
    { ngx_string("hello"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hello_loc_conf_t, name),
      &ngx_http_hello_p },
 
    ngx_null_command
};
 
 
static ngx_str_t hello_string;
 
/*
 * The module context has hooks , here we have a hook for creating
 * location configuration
 */
static ngx_http_module_t ngx_http_hello_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */
 
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
 
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
 
    ngx_http_hello_create_loc_conf, /* create location configuration */
    NULL                           /* merge location configuration */
};
 

/*
 * The module which binds the context and commands 
 * 
 */
ngx_module_t ngx_http_hello_module = {
    NGX_MODULE_V1,
    &ngx_http_hello_module_ctx,    /* module context */
    ngx_http_hello_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
add_chain_link(ngx_http_request_t *r, ngx_chain_t** chain, void *data, size_t len, 
    ngx_str_t* param, size_t* content_length)
{
    ngx_buf_t   *b;
    ngx_chain_t *tmp;
    ngx_str_t    s;
    size_t       total_len;

    total_len = (param) ? len + param->len : len;
    *content_length += total_len;

    s.data = ngx_pcalloc(r->pool, total_len); 
    //  TODO: error check 
    s.len = total_len;
    ngx_memcpy(s.data, data, len);

    if (param)
        ngx_memcpy(s.data + len, param->data, param->len);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
        "str:'%V' len:%d", &s, s.len);

    /* allocate a buffer for your response body */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = s.data;
    b->last = s.data + s.len;
    b->memory = 1;    /* this buffer is in memory */

    /* attach this buffer to the buffer chain */
    tmp = ngx_alloc_chain_link(r->pool);
    /* TODO: add error handling */

    tmp->buf = b;
    tmp->next = NULL;

    if (*chain) {
        (*chain)->next = tmp;
    }

    *chain = tmp;

    return NGX_OK;
}

static ngx_int_t
get_tocken(ngx_http_request_t *r, ngx_str_t* s)
{
    u_char *pos, *start;
    size_t  size;

    if (!r->args.data) {
        return 0;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "1.args:%V hello:%V", 
        &(r->args), &hello_string);
   
    start = pos = ngx_strlcasestrn(r->args.data, r->args.data + r->args.len, 
        hello_string.data, hello_string.len - 1);

    if (!pos) {
        return 0;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "2.args:%V", &(r->args));

    pos += hello_string.len;
    if (*pos++ != '=') {
        return 0;
    }

    while (pos < r->args.data + r->args.len) {
        if (*pos == '&') {
            break;
        }
        ++pos;
    }

    size = pos - start + 1;

    s->data = ngx_pcalloc(r->pool, size); 
    //  TODO: error check 
    s->len = size;

    s->data[0] = '?';
    ngx_memcpy(s->data+1, start, size-1);

    return 1;
}
 
/*
 * Main handler function of the module. 
 */
static ngx_int_t
ngx_http_hello_handler(ngx_http_request_t *r)
{
    ngx_int_t    rc;
    ngx_chain_t *head, *tail;
    u_char    *last, *addr, *p, *chain_start;
    size_t    root, cl;
    ngx_str_t path, tocken;

    u_char                     is_tag;
    ngx_uint_t                 level;
    ngx_log_t                 *log;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
 
    /* we response to 'GET' and 'HEAD' requests only */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }
 
    /* discard request body, since we don't need it here */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    ngx_log_error(NGX_LOG_ERR, log, 0, "playlist filename:%V", &path);
 
    /* set the 'Content-type' header */
    r->headers_out.content_type.len = sizeof(m3u8_content_type) - 1;
    r->headers_out.content_type.data = m3u8_content_type;

    /* get core module config */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool) != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    r->root_tested = !r->error_page;

    if (!get_tocken(r, &tocken)) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "tocken not found");
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_ERR, log, 0, "args:%V", &(r->args));

    /* mmap playlist file */
    addr = mmap(NULL, of.size, PROT_READ, MAP_SHARED, of.fd, 0);
    if (addr == MAP_FAILED) {

        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                  "mmap(%uz) \"%s\" failed", of.size, path);

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_ERR, log, 0, "after mmap");

    head = tail = NULL;
    p = chain_start = addr;
    cl = is_tag = 0;
    
    while (p < addr + of.size) {

        // switch (*p) {
        // case '#':
        //     is_tag = 1;
        //     ++p;
        //     break;

        // case '\r':
        // case '\n':
        //     /* eol */
        //     if (is_tag) {
        //         is_tag = 0;
        //         ++p;
        //     } else {
        //         rc = add_chain_link(r, &tail, chain_start, p - chain_start, 
        //             &hello_string, &cl);

        //         if (!head) {
        //             head = tail;
        //         }

        //         chain_start = p;
        //         is_tag = 0;
        //     }
        // }

        if (*p == '#') {
            is_tag = 1;
            ++p;
            continue;
        }

        if (*p == '\r' || *p == '\n') {

            // ngx_log_error(NGX_LOG_ERR, log, 0, "EOL");

            /* eol */
            if (is_tag) {
                is_tag = 0;
                ++p;
                continue;
                // ngx_log_error(NGX_LOG_ERR, log, 0, "IS TAG");
            }

            rc = add_chain_link(r, &tail, chain_start, p - chain_start, 
                &tocken, &cl);

            if (!head) {
                head = tail;
            }

            chain_start = p;
            is_tag = 0;
        }

        p++;
    }

    rc = add_chain_link(r, &tail, chain_start, p - chain_start, 
                        (is_tag) ? &tocken : NULL, &cl);

    /* this is the last buffer in the buffer chain */
    if (tail) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    ngx_log_error(NGX_LOG_ERR, log, 0, "before munmap:%d", of.size);

    if (munmap(addr, of.size) == -1) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "munmap failed:%d", of.size);
    }

    /* set the status line*/
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = cl;

    /* send the headers of your response */
    rc = ngx_http_send_header(r);

    /* send the header only, if the request type is http 'HEAD' */
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only || r->method == NGX_HTTP_HEAD) {
        return rc;
    }
 
    /* send the buffer chain of your response */
    return ngx_http_output_filter(r, head);
}
 
/*
 * Function for the directive hello , it validates its value
 * and copies it to a static variable to be printed later
 */
static char *
ngx_http_hello(ngx_conf_t *cf, void *post, void *data)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hello_handler;

    ngx_str_t *name = data; // i.e., first field of ngx_http_hello_loc_conf_t
    
    if (ngx_strcmp(name->data, "") == 0) {
        return NGX_CONF_ERROR;
    }
    hello_string.data = name->data;
    hello_string.len = ngx_strlen(hello_string.data);

    return NGX_CONF_OK;
}